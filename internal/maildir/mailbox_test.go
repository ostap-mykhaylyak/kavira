package maildir

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func deliverN(t *testing.T, root string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := Deliver(root, []byte("Subject: m\r\n\r\nbody"), -1, -1); err != nil {
			t.Fatal(err)
		}
		// Distinct mtimes so the delivery ordering is unambiguous.
		time.Sleep(2 * time.Millisecond)
	}
}

func TestUIDsStableAcrossReopen(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 3)

	mb, err := OpenMailbox(root, Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if mb.Count() != 3 {
		t.Fatalf("count = %d", mb.Count())
	}
	var first []uint32
	for _, m := range mb.Messages() {
		first = append(first, m.UID)
	}
	if first[0] != 1 || first[1] != 2 || first[2] != 3 {
		t.Errorf("UIDs = %v, want 1,2,3", first)
	}
	validity := mb.UIDValidity()

	// Reopen: same UIDs, same UIDVALIDITY.
	mb2, err := OpenMailbox(root, Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if mb2.UIDValidity() != validity {
		t.Errorf("UIDVALIDITY changed: %d -> %d", validity, mb2.UIDValidity())
	}
	for i, m := range mb2.Messages() {
		if m.UID != first[i] {
			t.Errorf("message %d: UID %d -> %d", i, first[i], m.UID)
		}
	}

	// A new delivery continues the sequence, never reusing a UID.
	deliverN(t, root, 1)
	if err := mb2.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := mb2.Messages()[3].UID; got != 4 {
		t.Errorf("new message UID = %d, want 4", got)
	}
	if mb2.UIDNext() != 5 {
		t.Errorf("UIDNEXT = %d, want 5", mb2.UIDNext())
	}
}

func TestUIDNotReusedAfterExpunge(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 3)
	mb, _ := OpenMailbox(root, Inbox)

	// Delete the last message, expunge it, deliver a new one.
	last := mb.Messages()[2]
	if err := mb.SetFlags(last, Flags{FlagDeleted}); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Expunge(); err != nil {
		t.Fatal(err)
	}
	deliverN(t, root, 1)
	if err := mb.Refresh(); err != nil {
		t.Fatal(err)
	}
	if mb.Count() != 3 {
		t.Fatalf("count = %d", mb.Count())
	}
	if got := mb.Messages()[2].UID; got != 4 {
		t.Errorf("UID after expunge = %d, want 4 (UID 3 must never be reused)", got)
	}
}

func TestSetFlagsMovesOutOfNew(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 1)
	mb, _ := OpenMailbox(root, Inbox)

	m := mb.Messages()[0]
	if !m.Recent || m.Dir != "new" {
		t.Fatalf("fresh message should be recent in new/: %+v", m)
	}
	if err := mb.SetFlags(m, Flags{FlagSeen}); err != nil {
		t.Fatal(err)
	}
	if m.Dir != "cur" || m.Recent {
		t.Errorf("flagged message must move to cur/ and lose recent: %+v", m)
	}
	if !m.Flags.Has(FlagSeen) {
		t.Errorf("flags = %v", m.Flags)
	}
	// The file really moved.
	if _, err := os.Stat(filepath.Join(root, "cur", m.Name)); err != nil {
		t.Errorf("file not in cur/: %v", err)
	}

	// Reopening preserves the flag and the UID.
	mb2, _ := OpenMailbox(root, Inbox)
	got := mb2.Messages()[0]
	if !got.Flags.Has(FlagSeen) || got.UID != m.UID {
		t.Errorf("after reopen: uid=%d flags=%v", got.UID, got.Flags)
	}
}

func TestExpungeReturnsDescendingSeqs(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 5)
	mb, _ := OpenMailbox(root, Inbox)

	// Delete messages 2 and 4.
	for _, seq := range []uint32{2, 4} {
		if err := mb.SetFlags(mb.BySeq(seq), Flags{FlagDeleted}); err != nil {
			t.Fatal(err)
		}
	}
	seqs, err := mb.Expunge()
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 2 || seqs[0] != 4 || seqs[1] != 2 {
		t.Errorf("expunged seqs = %v, want [4 2] (descending)", seqs)
	}
	if mb.Count() != 3 {
		t.Errorf("count = %d, want 3", mb.Count())
	}
	// Sequence numbers renumbered, UIDs untouched.
	for i, m := range mb.Messages() {
		if m.Seq != uint32(i+1) {
			t.Errorf("message %d has seq %d", i, m.Seq)
		}
	}
	if uids := []uint32{mb.Messages()[0].UID, mb.Messages()[1].UID, mb.Messages()[2].UID}; uids[0] != 1 || uids[1] != 3 || uids[2] != 5 {
		t.Errorf("UIDs after expunge = %v, want [1 3 5]", uids)
	}
}

func TestCountsAndFirstUnseen(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 3)
	mb, _ := OpenMailbox(root, Inbox)

	if mb.Recent() != 3 || mb.Unseen() != 3 {
		t.Errorf("recent=%d unseen=%d, want 3/3", mb.Recent(), mb.Unseen())
	}
	if mb.FirstUnseen() != 1 {
		t.Errorf("first unseen = %d", mb.FirstUnseen())
	}
	mb.SetFlags(mb.BySeq(1), Flags{FlagSeen})
	if mb.Unseen() != 2 || mb.FirstUnseen() != 2 {
		t.Errorf("unseen=%d first=%d", mb.Unseen(), mb.FirstUnseen())
	}
	if mb.Recent() != 2 {
		t.Errorf("recent = %d, want 2", mb.Recent())
	}
}

func TestAppendWithFlags(t *testing.T) {
	root := t.TempDir()
	mb, _ := OpenMailbox(root, Inbox)

	m, err := mb.Append([]byte("Subject: appended\r\n\r\nx"), Flags{FlagSeen, FlagDraft}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Flags.Has(FlagSeen) || !m.Flags.Has(FlagDraft) {
		t.Errorf("flags = %v", m.Flags)
	}
	if m.Dir != "cur" || m.Recent {
		t.Errorf("flagged append should land in cur/: %+v", m)
	}
	data, _ := m.Read()
	if string(data) != "Subject: appended\r\n\r\nx" {
		t.Errorf("content = %q", data)
	}
}

func TestFoldersAndCopy(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 1)

	if err := CreateFolder(root, "Sent"); err != nil {
		t.Fatal(err)
	}
	if err := CreateFolder(root, "Sent"); err == nil {
		t.Error("creating an existing folder must fail")
	}
	folders, err := Folders(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 2 || folders[0] != Inbox || folders[1] != "Sent" {
		t.Fatalf("folders = %v", folders)
	}

	inbox, _ := OpenMailbox(root, Inbox)
	if err := inbox.CopyTo(inbox.Messages()[0], "Sent"); err != nil {
		t.Fatal(err)
	}
	sent, _ := OpenMailbox(root, "Sent")
	if sent.Count() != 1 {
		t.Errorf("copy did not land in Sent: %d", sent.Count())
	}
	// The copy has its own UID space.
	if sent.Messages()[0].UID != 1 {
		t.Errorf("copied message UID = %d", sent.Messages()[0].UID)
	}
	// The original is still in INBOX.
	inbox.Refresh()
	if inbox.Count() != 1 {
		t.Errorf("copy must not move the original: %d", inbox.Count())
	}

	if err := DeleteFolder(root, Inbox); err == nil {
		t.Error("INBOX must not be deletable")
	}
	if err := DeleteFolder(root, "Sent"); err != nil {
		t.Fatal(err)
	}
	if folders, _ := Folders(root); len(folders) != 1 {
		t.Errorf("folders after delete = %v", folders)
	}
}

func TestCorruptUIDListGetsFreshValidity(t *testing.T) {
	root := t.TempDir()
	deliverN(t, root, 2)
	mb, _ := OpenMailbox(root, Inbox)
	old := mb.UIDValidity()

	if err := os.WriteFile(filepath.Join(root, uidListFile), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mb2, err := OpenMailbox(root, Inbox)
	if err != nil {
		t.Fatal(err)
	}
	if mb2.UIDValidity() == old {
		t.Error("a corrupt UID list must yield a fresh UIDVALIDITY so clients resync")
	}
	if mb2.Count() != 2 {
		t.Errorf("messages should still be listed: %d", mb2.Count())
	}
}

func TestFlagsParsing(t *testing.T) {
	// The flag separator is platform dependent, so build the names
	// through the same helper the code uses.
	if got := ParseFlags(FileName("1234.abc.host", Flags{FlagFlagged, FlagAnswered, FlagSeen})); !got.Has(FlagSeen) || !got.Has(FlagFlagged) || !got.Has(FlagAnswered) {
		t.Errorf("parsed = %v", got)
	}
	if got := ParseFlags("1234.abc.host"); len(got) != 0 {
		t.Errorf("message in new/ has no flags, got %v", got)
	}
	if got := BaseName(FileName("1234.abc.host", Flags{FlagSeen})); got != "1234.abc.host" {
		t.Errorf("base = %q", got)
	}
	// Flags render sorted, so the filename is canonical.
	f := Flags{FlagSeen}.Add(FlagAnswered).Add(FlagDeleted)
	if f.String() != "RST" {
		t.Errorf("flag string = %q, want RST", f.String())
	}
	if f.Remove(FlagSeen).String() != "RT" {
		t.Errorf("remove = %q", f.Remove(FlagSeen).String())
	}
	if got := (Flags{FlagSeen}).IMAPFlags(true); len(got) != 2 || got[0] != `\Seen` || got[1] != `\Recent` {
		t.Errorf("imap flags = %v", got)
	}
	if _, ok := FlagFromIMAP(`\Recent`); ok {
		t.Error(`\Recent is positional and must not map to a stored flag`)
	}
	if f, ok := FlagFromIMAP(`\seen`); !ok || f != FlagSeen {
		t.Error("IMAP flag matching must be case-insensitive")
	}
}
