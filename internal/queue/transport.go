package queue

import (
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"sort"
	"time"
)

// SMTPTransport delivers envelopes to the recipient domain's MX
// hosts. TLS is opportunistic (like Postfix "may"): STARTTLS is used
// when offered, without certificate validation — strict validation
// needs MTA-STS/DANE, which arrive in a later milestone. A refused
// STARTTLS falls back to the next MX.
type SMTPTransport struct {
	// Hostname is our EHLO identity (the public server hostname).
	Hostname string
	// Port overrides the destination port (default 25; tests).
	Port int
	// LookupMX overrides MX resolution (tests). Returns hosts in
	// preference order.
	LookupMX func(domain string) ([]string, error)
	// Timeout bounds dial and per-command waits.
	Timeout time.Duration
}

func (t *SMTPTransport) port() int {
	if t.Port != 0 {
		return t.Port
	}
	return 25
}

func (t *SMTPTransport) timeout() time.Duration {
	if t.Timeout != 0 {
		return t.Timeout
	}
	return 2 * time.Minute
}

// mxHosts resolves the delivery targets for a domain: its MX records
// by preference or, per RFC 5321, the domain itself when none exist.
func (t *SMTPTransport) mxHosts(domain string) ([]string, error) {
	if t.LookupMX != nil {
		return t.LookupMX(domain)
	}
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		// Implicit MX: fall back to the domain's A/AAAA.
		return []string{domain}, nil
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	hosts := make([]string, len(mxs))
	for i, mx := range mxs {
		hosts[i] = trimDot(mx.Host)
	}
	return hosts, nil
}

func trimDot(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		return h[:len(h)-1]
	}
	return h
}

// Deliver implements Transport: try each MX in order, stopping at the
// first success or permanent refusal.
func (t *SMTPTransport) Deliver(e *Envelope) error {
	hosts, err := t.mxHosts(e.Domain)
	if err != nil {
		return fmt.Errorf("mx lookup %s: %w", e.Domain, err)
	}
	var lastErr error = fmt.Errorf("no MX hosts for %s", e.Domain)
	for _, h := range hosts {
		err := t.trySend(h, e)
		if err == nil {
			return nil
		}
		var perm *PermanentError
		if errors.As(err, &perm) {
			return err // definitive answer from the responsible MX
		}
		lastErr = err
	}
	return lastErr
}

// trySend runs one SMTP transaction against one host.
func (t *SMTPTransport) trySend(host string, e *Envelope) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(t.port())), t.timeout())
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(t.timeout()))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return classify(err)
	}
	defer c.Close()

	if err := c.Hello(t.Hostname); err != nil {
		return classify(err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&stdtls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil {
			return classify(err)
		}
	}
	if err := c.Mail(e.From); err != nil {
		return classify(err)
	}
	if err := c.Rcpt(e.Rcpt); err != nil {
		return classify(err)
	}
	w, err := c.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := w.Write(e.Data); err != nil {
		return classify(err)
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return c.Quit()
}

// classify maps SMTP protocol errors: 5xx replies become permanent,
// everything else stays transient.
func classify(err error) error {
	var tperr *textproto.Error
	if errors.As(err, &tperr) && tperr.Code >= 500 && tperr.Code < 600 {
		return &PermanentError{Code: tperr.Code, Msg: tperr.Msg}
	}
	return err
}
