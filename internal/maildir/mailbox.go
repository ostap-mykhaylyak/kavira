package maildir

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// uidListFile holds the UID assignment of a mailbox. IMAP requires
// UIDs to be stable and strictly ascending for the lifetime of a
// UIDVALIDITY, which the filesystem alone cannot provide: the list
// maps each message's stable base name to the UID it was given.
//
// Format (first line is the header):
//
//	V<uidvalidity> N<uidnext>
//	<uid> <basename>
const uidListFile = "kavira-uidlist"

// Folder names of the Maildir++ layout. INBOX is the maildir root;
// every other folder is a "." prefixed subdirectory of it.
const (
	Inbox = "INBOX"
)

// Message is one message in a mailbox.
type Message struct {
	// UID is the IMAP unique identifier, stable across sessions.
	UID uint32
	// Seq is the 1-based sequence number within the current view.
	Seq uint32
	// Name is the current filename (flags included).
	Name string
	// Dir is "new" or "cur".
	Dir string
	// Flags are the Maildir flags parsed from the filename.
	Flags Flags
	// Recent reports whether the message is still in new/.
	Recent bool
	// Size is the message size in bytes.
	Size int64
	// Internal is the delivery timestamp (file mtime).
	Internal time.Time

	root   string
	folder string
}

// Path returns the message's full path on disk.
func (m *Message) Path() string {
	return filepath.Join(folderDir(m.root, m.folder), m.Dir, m.Name)
}

// Read returns the raw message bytes.
func (m *Message) Read() ([]byte, error) {
	return os.ReadFile(m.Path())
}

// Mailbox is one folder of a Maildir account, with its UID state
// loaded. A Mailbox is a snapshot: reopen (or call Refresh) to see
// messages delivered meanwhile.
type Mailbox struct {
	root     string // the account maildir (INBOX)
	folder   string // "INBOX" or a subfolder name
	messages []*Message

	uidValidity uint32
	uidNext     uint32
}

// folderDir maps a folder name onto its directory: INBOX is the root,
// anything else is the Maildir++ "." prefixed subdirectory.
func folderDir(root, folder string) string {
	if folder == "" || strings.EqualFold(folder, Inbox) {
		return root
	}
	return filepath.Join(root, "."+folder)
}

// OpenMailbox loads a folder of the account rooted at root, creating
// the Maildir layout if missing.
func OpenMailbox(root, folder string) (*Mailbox, error) {
	dir := folderDir(root, folder)
	for _, sub := range []string{"", "tmp", "new", "cur"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("mailbox %s: %w", folder, err)
		}
	}
	mb := &Mailbox{root: root, folder: folder}
	if err := mb.Refresh(); err != nil {
		return nil, err
	}
	return mb, nil
}

// UIDValidity returns the mailbox UIDVALIDITY.
func (mb *Mailbox) UIDValidity() uint32 { return mb.uidValidity }

// UIDNext returns the UID the next delivered message will receive.
func (mb *Mailbox) UIDNext() uint32 { return mb.uidNext }

// Folder returns the mailbox name.
func (mb *Mailbox) Folder() string { return mb.folder }

// Messages returns the current snapshot, ordered by UID (which is
// also sequence order).
func (mb *Mailbox) Messages() []*Message { return mb.messages }

// Count returns the number of messages.
func (mb *Mailbox) Count() int { return len(mb.messages) }

// Recent counts the messages still in new/.
func (mb *Mailbox) Recent() int {
	n := 0
	for _, m := range mb.messages {
		if m.Recent {
			n++
		}
	}
	return n
}

// Unseen counts the messages without the Seen flag.
func (mb *Mailbox) Unseen() int {
	n := 0
	for _, m := range mb.messages {
		if !m.Flags.Has(FlagSeen) {
			n++
		}
	}
	return n
}

// FirstUnseen returns the sequence number of the first unseen
// message, or 0 when every message is seen.
func (mb *Mailbox) FirstUnseen() uint32 {
	for _, m := range mb.messages {
		if !m.Flags.Has(FlagSeen) {
			return m.Seq
		}
	}
	return 0
}

// ByUID returns the message with the given UID.
func (mb *Mailbox) ByUID(uid uint32) *Message {
	for _, m := range mb.messages {
		if m.UID == uid {
			return m
		}
	}
	return nil
}

// BySeq returns the message at a 1-based sequence number.
func (mb *Mailbox) BySeq(seq uint32) *Message {
	if seq < 1 || int(seq) > len(mb.messages) {
		return nil
	}
	return mb.messages[seq-1]
}

// Refresh rescans the folder and assigns UIDs to newly arrived
// messages, persisting the UID list.
func (mb *Mailbox) Refresh() error {
	dir := folderDir(mb.root, mb.folder)

	uids, validity, next, err := mb.readUIDList()
	if err != nil {
		return err
	}
	mb.uidValidity = validity

	type entry struct {
		name, sub string
		info      os.FileInfo
	}
	var found []entry
	for _, sub := range []string{"new", "cur"} {
		ents, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue // vanished between listing and stat
			}
			found = append(found, entry{name: e.Name(), sub: sub, info: info})
		}
	}

	// Assign UIDs to unknown messages in delivery order, so a batch
	// arriving between two scans keeps a sensible ordering.
	sort.Slice(found, func(i, j int) bool {
		return found[i].info.ModTime().Before(found[j].info.ModTime())
	})
	dirty := false
	for _, e := range found {
		base := BaseName(e.name)
		if _, ok := uids[base]; !ok {
			uids[base] = next
			next++
			dirty = true
		}
	}

	msgs := make([]*Message, 0, len(found))
	for _, e := range found {
		base := BaseName(e.name)
		msgs = append(msgs, &Message{
			UID:      uids[base],
			Name:     e.name,
			Dir:      e.sub,
			Flags:    ParseFlags(e.name),
			Recent:   e.sub == "new",
			Size:     e.info.Size(),
			Internal: e.info.ModTime(),
			root:     mb.root,
			folder:   mb.folder,
		})
	}
	// IMAP requires sequence order to follow UID order.
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].UID < msgs[j].UID })
	for i, m := range msgs {
		m.Seq = uint32(i + 1)
	}
	mb.messages = msgs
	mb.uidNext = next

	if dirty {
		// Prune entries for messages that no longer exist, so the
		// list cannot grow forever.
		live := make(map[string]uint32, len(msgs))
		for _, m := range msgs {
			live[BaseName(m.Name)] = m.UID
		}
		return mb.writeUIDList(live, mb.uidValidity, next)
	}
	return nil
}

// newUIDValidity mints a UIDVALIDITY. It must differ from any value
// previously handed out for the same mailbox: whenever the UID list
// is lost, UIDs restart from 1, and a client that saw the same
// UIDVALIDITY would keep its cache and silently map stale UIDs onto
// different messages. A second-resolution timestamp can repeat within
// the same second, so the nanosecond clock is used for entropy.
func newUIDValidity() uint32 {
	v := uint32(time.Now().UnixNano())
	if v == 0 {
		v = 1 // 0 is not a valid UIDVALIDITY
	}
	return v
}

// readUIDList loads the persisted UID assignment, creating it on
// first use. A missing or corrupt list gets a fresh UIDVALIDITY:
// clients then resynchronize from scratch, which is the documented
// recovery path rather than silently reusing UIDs.
func (mb *Mailbox) readUIDList() (map[string]uint32, uint32, uint32, error) {
	path := filepath.Join(folderDir(mb.root, mb.folder), uidListFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]uint32{}, newUIDValidity(), 1, nil
		}
		return nil, 0, 0, err
	}
	defer f.Close()

	uids := map[string]uint32{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !sc.Scan() {
		return uids, newUIDValidity(), 1, nil
	}
	var validity, next uint64
	header := strings.Fields(sc.Text())
	if len(header) != 2 || !strings.HasPrefix(header[0], "V") || !strings.HasPrefix(header[1], "N") {
		return map[string]uint32{}, newUIDValidity(), 1, nil
	}
	validity, err1 := strconv.ParseUint(header[0][1:], 10, 32)
	next, err2 := strconv.ParseUint(header[1][1:], 10, 32)
	if err1 != nil || err2 != nil || next < 1 {
		return map[string]uint32{}, newUIDValidity(), 1, nil
	}

	for sc.Scan() {
		line := sc.Text()
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		uid, err := strconv.ParseUint(line[:sp], 10, 32)
		if err != nil {
			continue
		}
		uids[line[sp+1:]] = uint32(uid)
	}
	return uids, uint32(validity), uint32(next), nil
}

// writeUIDList persists the assignment atomically.
func (mb *Mailbox) writeUIDList(uids map[string]uint32, validity, next uint32) error {
	dir := folderDir(mb.root, mb.folder)
	path := filepath.Join(dir, uidListFile)

	var b strings.Builder
	fmt.Fprintf(&b, "V%d N%d\n", validity, next)
	// Sorted by UID: the file stays diffable and reads back in order.
	type kv struct {
		base string
		uid  uint32
	}
	list := make([]kv, 0, len(uids))
	for base, uid := range uids {
		list = append(list, kv{base, uid})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].uid < list[j].uid })
	for _, e := range list {
		fmt.Fprintf(&b, "%d %s\n", e.uid, e.base)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SetFlags replaces a message's flags, renaming it accordingly. A
// message in new/ moves to cur/ as soon as it acquires any flag,
// which is how Maildir records that it is no longer recent.
func (mb *Mailbox) SetFlags(m *Message, f Flags) error {
	dir := folderDir(mb.root, mb.folder)
	newName := FileName(BaseName(m.Name), f)
	newSub := "cur"
	oldPath := filepath.Join(dir, m.Dir, m.Name)
	newPath := filepath.Join(dir, newSub, newName)
	if oldPath != newPath {
		if err := os.Rename(oldPath, newPath); err != nil {
			return err
		}
	}
	m.Name = newName
	m.Dir = newSub
	m.Flags = f
	m.Recent = false
	return nil
}

// Expunge permanently removes every message flagged Deleted and
// returns their sequence numbers, highest first (the order IMAP
// clients expect EXPUNGE responses in).
func (mb *Mailbox) Expunge() ([]uint32, error) {
	var seqs []uint32
	var kept []*Message
	for _, m := range mb.messages {
		if m.Flags.Has(FlagDeleted) {
			if err := os.Remove(m.Path()); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			seqs = append(seqs, m.Seq)
			continue
		}
		kept = append(kept, m)
	}
	if len(seqs) == 0 {
		return nil, nil
	}
	for i, m := range kept {
		m.Seq = uint32(i + 1)
	}
	mb.messages = kept
	// Highest sequence first: each removal shifts the ones above it.
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] > seqs[j] })
	return seqs, nil
}

// Append stores a message directly into the mailbox with the given
// flags (IMAP APPEND), bypassing new/ when flags are present.
func (mb *Mailbox) Append(data []byte, f Flags, internal time.Time) (*Message, error) {
	dir := folderDir(mb.root, mb.folder)
	path, err := Deliver(dir, data, -1, -1)
	if err != nil {
		return nil, err
	}
	if !internal.IsZero() {
		os.Chtimes(path, internal, internal)
	}
	if len(f) > 0 {
		base := BaseName(filepath.Base(path))
		target := filepath.Join(dir, "cur", FileName(base, f))
		if err := os.Rename(path, target); err != nil {
			return nil, err
		}
	}
	if err := mb.Refresh(); err != nil {
		return nil, err
	}
	// The appended message is the highest UID.
	if n := len(mb.messages); n > 0 {
		return mb.messages[n-1], nil
	}
	return nil, fmt.Errorf("appended message not found after refresh")
}

// CopyTo copies a message into another folder of the same account.
func (mb *Mailbox) CopyTo(m *Message, folder string) error {
	data, err := m.Read()
	if err != nil {
		return err
	}
	dst, err := OpenMailbox(mb.root, folder)
	if err != nil {
		return err
	}
	_, err = dst.Append(data, m.Flags, m.Internal)
	return err
}

// Folders lists the mailboxes of an account: INBOX plus every
// Maildir++ subfolder.
func Folders(root string) ([]string, error) {
	out := []string{Inbox}
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := e.Name()[1:]
		if name == "" || name == "." {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out[1:])
	return out, nil
}

// CreateFolder creates a Maildir++ subfolder.
func CreateFolder(root, folder string) error {
	if strings.EqualFold(folder, Inbox) {
		return fmt.Errorf("INBOX already exists")
	}
	dir := folderDir(root, folder)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("mailbox already exists")
	}
	for _, sub := range []string{"", "tmp", "new", "cur"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	return nil
}

// DeleteFolder removes a Maildir++ subfolder and its messages.
func DeleteFolder(root, folder string) error {
	if strings.EqualFold(folder, Inbox) {
		return fmt.Errorf("cannot delete INBOX")
	}
	dir := folderDir(root, folder)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("mailbox does not exist")
	}
	return os.RemoveAll(dir)
}
