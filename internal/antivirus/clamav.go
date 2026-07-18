// Package antivirus scans messages with ClamAV over its socket,
// using the INSTREAM command so no temporary file is written and
// clamd needs no access to the queue.
//
// A scanner that cannot reach clamd reports an error rather than a
// clean verdict: the caller decides whether an unreachable antivirus
// means "accept" or "defer", and that policy belongs in the SMTP
// layer, not here.
package antivirus

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// chunkSize is the INSTREAM chunk length. clamd's default
// StreamMaxLength is 25 MB, comfortably above a normal message.
const chunkSize = 32 * 1024

// ClamAV talks to clamd over a unix or TCP socket.
type ClamAV struct {
	// Network is "unix" or "tcp".
	Network string
	// Address is the socket path or host:port.
	Address string
	// Timeout bounds the whole scan.
	Timeout time.Duration
}

// New builds a ClamAV scanner from a config address: a path starting
// with '/' is a unix socket, anything else is host:port.
func New(address string, timeout time.Duration) *ClamAV {
	network := "tcp"
	if strings.HasPrefix(address, "/") {
		network = "unix"
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ClamAV{Network: network, Address: address, Timeout: timeout}
}

// Ping checks that clamd is reachable and responding.
func (c *ClamAV) Ping() error {
	conn, err := net.DialTimeout(c.Network, c.Address, c.Timeout)
	if err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	if !strings.Contains(string(buf[:n]), "PONG") {
		return fmt.Errorf("clamav: unexpected ping reply %q", buf[:n])
	}
	return nil
}

// Scan returns the malware name, or "" when the message is clean.
func (c *ClamAV) Scan(data []byte) (string, error) {
	conn, err := net.DialTimeout(c.Network, c.Address, c.Timeout)
	if err != nil {
		return "", fmt.Errorf("clamav: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", fmt.Errorf("clamav: %w", err)
	}
	// Each chunk is a 4-byte big-endian length followed by the data;
	// a zero length ends the stream.
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(end-off))
		if _, err := conn.Write(hdr[:]); err != nil {
			return "", fmt.Errorf("clamav: %w", err)
		}
		if _, err := conn.Write(data[off:end]); err != nil {
			return "", fmt.Errorf("clamav: %w", err)
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", fmt.Errorf("clamav: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("clamav: %w", err)
	}
	reply := strings.TrimRight(string(buf[:n]), "\x00\n ")

	switch {
	case strings.HasSuffix(reply, "OK"):
		return "", nil
	case strings.HasSuffix(reply, "FOUND"):
		// "stream: Eicar-Test-Signature FOUND"
		name := strings.TrimSuffix(reply, " FOUND")
		if _, after, ok := strings.Cut(name, ": "); ok {
			name = after
		}
		return name, nil
	case strings.Contains(reply, "ERROR"):
		return "", fmt.Errorf("clamav: %s", reply)
	}
	return "", fmt.Errorf("clamav: unexpected reply %q", reply)
}
