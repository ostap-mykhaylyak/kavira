// Package status exposes the running daemon's state over a local unix
// socket, and formats it for `kavira status`.
//
// The socket is deliberately not a network port and carries no
// credentials: it is readable only by root and the service user, so
// asking a server about itself needs no API key and cannot be done
// from another machine. The administrative API remains the remote
// interface; this is the one an operator uses over SSH right after
// starting the service.
package status

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/kavira/internal/stats"
)

// Report is the daemon's answer, versioned so an old client talking
// to a new daemon fails cleanly rather than misreporting.
type Report struct {
	Schema   int    `json:"schema"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
	PID      int    `json:"pid"`
	Uptime   string `json:"uptime"`

	Domains   []DomainInfo `json:"domains"`
	Mailboxes int          `json:"mailboxes"`
	Listeners []Listener   `json:"listeners"`
	TLSLoaded []string     `json:"tls_loaded"`

	QueueDepth int `json:"queue_depth"`

	Counters stats.Snapshot `json:"counters"`

	// Warnings are the current configuration warnings, and
	// ReloadError the last failed reload, so a half-applied change is
	// visible without reading the log.
	Warnings    []string `json:"warnings,omitempty"`
	ReloadError string   `json:"reload_error,omitempty"`
}

// schemaVersion is bumped when the report shape changes.
const schemaVersion = 1

// DomainInfo is one hosted domain.
type DomainInfo struct {
	Name      string `json:"name"`
	Storage   string `json:"storage"`
	Mailboxes int    `json:"mailboxes"`
	DKIM      bool   `json:"dkim"`
}

// Listener is one protocol endpoint.
type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

// Serve accepts status queries on a unix socket at path until stop is
// closed. build produces a fresh report per connection.
func Serve(path string, build func() Report, stop <-chan struct{}) error {
	// A stale socket from a crashed run would block the bind.
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("status socket %s: %w", path, err)
	}
	// Owner and group only: the socket exposes configuration details.
	os.Chmod(path, 0o660)

	go func() {
		<-stop
		ln.Close()
		os.Remove(path)
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				rep := build()
				json.NewEncoder(conn).Encode(rep)
			}()
		}
	}()
	return nil
}

// Query asks the daemon at path for its status.
func Query(path string) (*Report, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the daemon on %s: %w\n"+
			"is kavira running? (systemctl status kavira)", path, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var rep Report
	if err := json.NewDecoder(conn).Decode(&rep); err != nil {
		return nil, fmt.Errorf("unreadable status reply: %w", err)
	}
	if rep.Schema != schemaVersion {
		return nil, fmt.Errorf("status schema %d, this client speaks %d: "+
			"the running daemon is a different version than this binary",
			rep.Schema, schemaVersion)
	}
	return &rep, nil
}

// Build assembles a report. Called per query, so every field is live.
func Build(version, hostname string, started time.Time, domains []DomainInfo,
	mailboxes int, listeners []Listener, tlsLoaded []string, queueDepth int,
	counters *stats.Counters, warnings []string, reloadErr string) Report {
	return Report{
		Schema:      schemaVersion,
		Version:     version,
		Hostname:    hostname,
		PID:         os.Getpid(),
		Uptime:      time.Since(started).Round(time.Second).String(),
		Domains:     domains,
		Mailboxes:   mailboxes,
		Listeners:   listeners,
		TLSLoaded:   tlsLoaded,
		QueueDepth:  queueDepth,
		Counters:    counters.Snapshot(),
		Warnings:    warnings,
		ReloadError: reloadErr,
	}
}

// Print renders a report for a terminal.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "kavira %s  %s\n", r.Version, r.Hostname)
	fmt.Fprintf(w, "  pid %d, up %s\n\n", r.PID, r.Uptime)

	fmt.Fprintf(w, "Listeners\n")
	if len(r.Listeners) == 0 {
		fmt.Fprintf(w, "  none\n")
	}
	for _, l := range r.Listeners {
		fmt.Fprintf(w, "  %-12s %s\n", l.Protocol, l.Address)
	}

	fmt.Fprintf(w, "\nTLS\n")
	if len(r.TLSLoaded) == 0 {
		fmt.Fprintf(w, "  no certificate loaded (submission, IMAP, POP3 and the API do not start)\n")
	} else {
		fmt.Fprintf(w, "  %s\n", strings.Join(r.TLSLoaded, ", "))
	}

	fmt.Fprintf(w, "\nDomains (%d, %d mailboxes)\n", len(r.Domains), r.Mailboxes)
	if len(r.Domains) == 0 {
		fmt.Fprintf(w, "  none: this server accepts no mail\n")
	}
	sorted := append([]DomainInfo(nil), r.Domains...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, d := range sorted {
		dkim := "unsigned"
		if d.DKIM {
			dkim = "dkim"
		}
		fmt.Fprintf(w, "  %-30s %-12s %3d mailbox(es)  %s\n", d.Name, d.Storage, d.Mailboxes, dkim)
	}

	c := r.Counters
	fmt.Fprintf(w, "\nMail since start\n")
	fmt.Fprintf(w, "  inbound     %d received, %d rejected, %d spam, %d relay denied\n",
		c.Received, c.Rejected, c.Spam, c.RelayDeny)
	fmt.Fprintf(w, "  submission  %d accepted, %d auth ok, %d auth failed\n",
		c.Submitted, c.AuthOK, c.AuthFail)
	fmt.Fprintf(w, "  outbound    %d delivered, %d deferred, %d bounced\n",
		c.Delivered, c.Deferred, c.Bounced)
	fmt.Fprintf(w, "  queue       %d waiting\n", r.QueueDepth)

	if r.ReloadError != "" {
		fmt.Fprintf(w, "\nLast reload FAILED, the previous configuration is still active:\n  %s\n", r.ReloadError)
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "\nwarning: %s\n", warn)
	}
}
