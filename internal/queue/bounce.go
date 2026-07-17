package queue

import (
	"bytes"
	"fmt"
	"time"
)

// maxOriginalHeaders caps how much of the failed message a bounce
// carries back.
const maxOriginalHeaders = 8 * 1024

// BuildBounce composes an RFC 3464 delivery status notification for a
// failed envelope. It returns nil when no bounce must be generated:
// a null reverse-path means the failed message was itself a
// notification, and notifications are never bounced (mail loops).
func BuildBounce(hostname string, e *Envelope, reason string) []byte {
	if e.From == "" {
		return nil
	}
	boundary := fmt.Sprintf("kavira-dsn-%s", e.ID)
	var b bytes.Buffer

	fmt.Fprintf(&b, "From: Mail Delivery System <MAILER-DAEMON@%s>\r\n", hostname)
	fmt.Fprintf(&b, "To: <%s>\r\n", e.From)
	fmt.Fprintf(&b, "Subject: Undelivered Mail Returned to Sender\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Auto-Submitted: auto-replied\r\n")
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"%s\"\r\n", boundary)
	fmt.Fprintf(&b, "\r\n")

	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	fmt.Fprintf(&b, "This is the mail system at host %s.\r\n\r\n", hostname)
	fmt.Fprintf(&b, "Your message could not be delivered to:\r\n\r\n\t<%s>\r\n\r\n", e.Rcpt)
	fmt.Fprintf(&b, "Reason: %s\r\n", reason)

	fmt.Fprintf(&b, "\r\n--%s\r\nContent-Type: message/delivery-status\r\n\r\n", boundary)
	fmt.Fprintf(&b, "Reporting-MTA: dns; %s\r\n\r\n", hostname)
	fmt.Fprintf(&b, "Final-Recipient: rfc822; %s\r\n", e.Rcpt)
	fmt.Fprintf(&b, "Action: failed\r\n")
	fmt.Fprintf(&b, "Status: 5.0.0\r\n")
	fmt.Fprintf(&b, "Diagnostic-Code: smtp; %s\r\n", reason)

	fmt.Fprintf(&b, "\r\n--%s\r\nContent-Type: text/rfc822-headers\r\n\r\n", boundary)
	b.Write(originalHeaders(e.Data))
	fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
	return b.Bytes()
}

// originalHeaders extracts the header block of the failed message.
func originalHeaders(data []byte) []byte {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(data)
	}
	if end > maxOriginalHeaders {
		end = maxOriginalHeaders
	}
	return data[:end]
}
