package maildir

import (
	"sort"
	"strings"
)

// Flag is one Maildir message flag, encoded in the filename after the
// ":2," separator (RFC-less but universal Maildir convention).
type Flag rune

const (
	FlagDraft    Flag = 'D'
	FlagFlagged  Flag = 'F'
	FlagPassed   Flag = 'P'
	FlagAnswered Flag = 'R'
	FlagSeen     Flag = 'S'
	FlagDeleted  Flag = 'T'
)

// infoSep separates the unique name from the flag info in a Maildir
// filename: "<unique>:2,<flags>". The separator character is platform
// dependent (see infoChar): ':' is reserved on NTFS, where it opens an
// alternate data stream, so Windows uses ';' — the same fallback
// Dovecot applies on filesystems that reject the colon. Production is
// Linux and uses the standard ':'.
const infoSep = infoChar + "2,"

// Flags is a set of Maildir flags, kept sorted for the filename.
type Flags []Flag

// ParseFlags extracts the flags from a Maildir filename. A name
// without the ":2," part (i.e. a message in new/) carries no flags.
func ParseFlags(name string) Flags {
	i := strings.Index(name, infoSep)
	if i < 0 {
		return nil
	}
	var f Flags
	for _, r := range name[i+len(infoSep):] {
		switch Flag(r) {
		case FlagDraft, FlagFlagged, FlagPassed, FlagAnswered, FlagSeen, FlagDeleted:
			if !f.Has(Flag(r)) {
				f = append(f, Flag(r))
			}
		}
	}
	f.sort()
	return f
}

// BaseName returns the filename without the flag part. It is stable
// across flag changes, so it is what the UID list keys on.
func BaseName(name string) string {
	if i := strings.Index(name, infoSep); i >= 0 {
		return name[:i]
	}
	return name
}

// Has reports whether the set contains f.
func (f Flags) Has(x Flag) bool {
	for _, v := range f {
		if v == x {
			return true
		}
	}
	return false
}

// Add returns the set with x included.
func (f Flags) Add(x Flag) Flags {
	if f.Has(x) {
		return f
	}
	out := append(append(Flags(nil), f...), x)
	out.sort()
	return out
}

// Remove returns the set without x.
func (f Flags) Remove(x Flag) Flags {
	var out Flags
	for _, v := range f {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func (f Flags) sort() {
	sort.Slice(f, func(i, j int) bool { return f[i] < f[j] })
}

// String renders the flags as they appear in a filename.
func (f Flags) String() string {
	var b strings.Builder
	for _, v := range f {
		b.WriteRune(rune(v))
	}
	return b.String()
}

// FileName builds the filename for a base name and flag set.
func FileName(base string, f Flags) string {
	return base + infoSep + f.String()
}

// IMAPFlags renders the set as IMAP system flags, adding \Recent when
// recent is true (a message still sitting in new/).
func (f Flags) IMAPFlags(recent bool) []string {
	var out []string
	if f.Has(FlagSeen) {
		out = append(out, `\Seen`)
	}
	if f.Has(FlagAnswered) {
		out = append(out, `\Answered`)
	}
	if f.Has(FlagFlagged) {
		out = append(out, `\Flagged`)
	}
	if f.Has(FlagDeleted) {
		out = append(out, `\Deleted`)
	}
	if f.Has(FlagDraft) {
		out = append(out, `\Draft`)
	}
	if recent {
		out = append(out, `\Recent`)
	}
	return out
}

// FlagFromIMAP maps an IMAP system flag onto a Maildir flag. ok is
// false for flags with no Maildir equivalent (notably \Recent, which
// is positional, not stored).
func FlagFromIMAP(name string) (Flag, bool) {
	switch strings.ToLower(name) {
	case `\seen`:
		return FlagSeen, true
	case `\answered`:
		return FlagAnswered, true
	case `\flagged`:
		return FlagFlagged, true
	case `\deleted`:
		return FlagDeleted, true
	case `\draft`:
		return FlagDraft, true
	}
	return 0, false
}
