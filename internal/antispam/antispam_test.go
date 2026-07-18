package antispam

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trainCorpus feeds a small but distinctive ham/spam corpus.
func trainCorpus(t *testing.T, b *Bayes) {
	t.Helper()
	for i := 0; i < 30; i++ {
		ham := fmt.Sprintf("From: collega@azienda.it\r\nSubject: riunione progetto %d\r\n\r\n"+
			"Ciao, confermo la riunione di domani sul progetto. "+
			"Allego il verbale precedente e le note tecniche. Saluti.\r\n", i)
		b.Train([]byte(ham), false)

		spam := fmt.Sprintf("From: winner@lottery.tld\r\nSubject: CONGRATULATIONS you won %d\r\n\r\n"+
			"Click here now to claim your free prize money! "+
			"Viagra cheap pills discount casino jackpot winner urgent transfer.\r\n", i)
		b.Train([]byte(spam), true)
	}
}

func TestBayesClassifies(t *testing.T) {
	b, err := NewBayes("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Score([]byte("From: a@b.it\r\n\r\ntest")); ok {
		t.Error("an untrained classifier must have no opinion")
	}
	trainCorpus(t, b)
	if !b.Ready() {
		t.Fatal("classifier should be ready after 30+30 messages")
	}

	hamScore, ok := b.Score([]byte("From: collega@azienda.it\r\nSubject: riunione di lunedi\r\n\r\n" +
		"Confermo la riunione, allego il verbale e le note tecniche del progetto.\r\n"))
	if !ok {
		t.Fatal("want an opinion on ham")
	}
	spamScore, ok := b.Score([]byte("From: winner@lottery.tld\r\nSubject: CONGRATULATIONS\r\n\r\n" +
		"Click here now to claim your free prize money jackpot casino discount pills!\r\n"))
	if !ok {
		t.Fatal("want an opinion on spam")
	}
	if hamScore >= 0.5 {
		t.Errorf("ham scored %.3f, want < 0.5", hamScore)
	}
	if spamScore <= 0.5 {
		t.Errorf("spam scored %.3f, want > 0.5", spamScore)
	}
	if spamScore <= hamScore {
		t.Errorf("spam (%.3f) must score above ham (%.3f)", spamScore, hamScore)
	}
}

func TestBayesPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bayes")
	b, _ := NewBayes(path)
	trainCorpus(t, b)
	before, _ := b.Score([]byte("Subject: CONGRATULATIONS\r\n\r\nfree prize money jackpot casino"))
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}

	b2, err := NewBayes(path)
	if err != nil {
		t.Fatal(err)
	}
	ham, spam := b2.Trained()
	if ham != 30 || spam != 30 {
		t.Fatalf("reloaded counts = %d/%d, want 30/30", ham, spam)
	}
	after, ok := b2.Score([]byte("Subject: CONGRATULATIONS\r\n\r\nfree prize money jackpot casino"))
	if !ok {
		t.Fatal("reloaded classifier has no opinion")
	}
	if diff := after - before; diff > 0.001 || diff < -0.001 {
		t.Errorf("score changed across save/load: %.4f -> %.4f", before, after)
	}
}

func TestBayesLogSpaceNoUnderflow(t *testing.T) {
	// A message with many strongly-spammy tokens must not underflow
	// to a nonsensical score: naive multiplication would hit zero.
	b, _ := NewBayes("")
	trainCorpus(t, b)
	body := strings.Repeat("free prize money jackpot casino viagra discount urgent winner ", 50)
	score, ok := b.Score([]byte("Subject: CONGRATULATIONS\r\n\r\n" + body))
	if !ok {
		t.Fatal("want an opinion")
	}
	if score != score { // NaN check
		t.Fatal("score is NaN")
	}
	if score <= 0.5 || score > 1 {
		t.Errorf("score = %v, want a sane value above 0.5", score)
	}
}

func TestHeuristicRules(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"no message id", "From: a@b.it\r\nDate: Mon, 1 Jan 2026 00:00:00 +0000\r\nTo: c@d.it\r\nSubject: x\r\n\r\nbody", "NO_MESSAGE_ID"},
		{"raw ip link", "From: a@b.it\r\nMessage-ID: <1@b.it>\r\nDate: x\r\nTo: c@d.it\r\nSubject: s\r\n\r\nvisit http://192.0.2.1/login now", "URL_IS_RAW_IP"},
		{"shouty subject", "From: a@b.it\r\nMessage-ID: <1@b.it>\r\nDate: x\r\nTo: c@d.it\r\nSubject: URGENT ACTION REQUIRED NOW\r\n\r\nbody", "SUBJECT_ALL_CAPS"},
		{"display name spoof", "From: \"servizio@banca.it\" <ladro@evil.tld>\r\nMessage-ID: <1@b.it>\r\nDate: x\r\nTo: c@d.it\r\nSubject: s\r\n\r\nbody", "FROM_DISPLAY_NAME_SPOOF"},
	}
	for _, c := range cases {
		a := AnalyzeHeaders([]byte(c.msg))
		found := false
		for _, r := range a.Rules {
			if r.Name == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: rule %s did not fire, got %v", c.name, c.want, a.Names())
		}
	}
}

func TestExecutableAttachmentDetected(t *testing.T) {
	msg := "From: a@b.it\r\nMessage-ID: <1@b.it>\r\nDate: x\r\nTo: c@d.it\r\nSubject: fattura\r\n" +
		"Content-Type: multipart/mixed; boundary=xyz\r\n\r\n" +
		"--xyz\r\nContent-Type: application/octet-stream; name=\"fattura.pdf.exe\"\r\n\r\ndata\r\n--xyz--\r\n"
	a := AnalyzeHeaders([]byte(msg))
	if a.BadAttachment != "fattura.pdf.exe" {
		t.Errorf("bad attachment = %q", a.BadAttachment)
	}
	names := strings.Join(a.Names(), ",")
	if !strings.Contains(names, "EXECUTABLE_ATTACHMENT") {
		t.Errorf("rules = %s", names)
	}
	// The double extension is the disguise, and must be flagged too.
	if !strings.Contains(names, "DOUBLE_EXTENSION") {
		t.Errorf("double extension not flagged: %s", names)
	}
}

func TestURIDomainsExtracted(t *testing.T) {
	msg := "From: a@b.it\r\n\r\nvedi https://Esempio.TLD/path e http://altro.tld?x=1"
	a := AnalyzeHeaders([]byte(msg))
	if len(a.URIDomains) != 2 || a.URIDomains[0] != "esempio.tld" || a.URIDomains[1] != "altro.tld" {
		t.Errorf("uri domains = %v", a.URIDomains)
	}
}

// stubLister lists exactly one domain.
type stubLister struct{ bad string }

func (s stubLister) ListedDomain(d string) bool { return d == s.bad }

// stubScanner reports a virus when the body contains a marker.
type stubScanner struct{}

func (stubScanner) Scan(data []byte) (string, error) {
	if strings.Contains(string(data), "EICAR") {
		return "Eicar-Test-Signature", nil
	}
	return "", nil
}

func TestEngineCombinesSignals(t *testing.T) {
	b, _ := NewBayes("")
	trainCorpus(t, b)
	e := &Engine{Bayes: b, URIBL: stubLister{bad: "malicious.tld"}, Scanner: stubScanner{}}

	clean := []byte("From: collega@azienda.it\r\nMessage-ID: <1@azienda.it>\r\n" +
		"Date: Mon, 1 Jan 2026 00:00:00 +0000\r\nTo: me@azienda.it\r\nSubject: verbale riunione\r\n\r\n" +
		"Confermo la riunione di domani, allego il verbale e le note tecniche del progetto.\r\n")
	v := e.Check(clean)
	if v.Score >= 10 {
		t.Errorf("clean message scored %.1f (rules %v, bayes %.3f)", v.Score, v.Rules, v.Bayes)
	}

	// A blacklisted link adds a decisive amount.
	listed := []byte("From: a@b.it\r\nMessage-ID: <1@b.it>\r\nDate: x\r\nTo: c@d.it\r\nSubject: offerta\r\n\r\n" +
		"vai su https://malicious.tld/win\r\n")
	v = e.Check(listed)
	if !strings.Contains(strings.Join(v.Rules, ","), "URIBL_LISTED") {
		t.Errorf("URIBL rule did not fire: %v", v.Rules)
	}

	// A virus pins the score to the maximum whatever else says.
	v = e.Check([]byte("From: a@b.it\r\n\r\nEICAR payload"))
	if v.Virus == "" || v.Score != 100 {
		t.Errorf("virus verdict = %q score %.1f, want a named virus at 100", v.Virus, v.Score)
	}
}

func TestVerdictHeader(t *testing.T) {
	v := Verdict{Score: 12.5, Rules: []string{"NO_MESSAGE_ID", "BAYES_80"}}
	h := v.Header(5)
	if !strings.HasPrefix(h, "X-Spam-Status: Yes, score=12.5 required=5.0") {
		t.Errorf("header = %q", h)
	}
	if !strings.Contains(h, "tests=NO_MESSAGE_ID,BAYES_80") {
		t.Errorf("header missing tests: %q", h)
	}
	if !strings.HasSuffix(h, "\r\n") {
		t.Error("header must be CRLF terminated")
	}
	if clean := (Verdict{Score: 1}).Header(5); !strings.HasPrefix(clean, "X-Spam-Status: No") {
		t.Errorf("clean header = %q", clean)
	}
}

func TestSaveIsAtomicAndSkipsWhenClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bayes")
	b, _ := NewBayes(path)
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	// Nothing learned yet: no file should have been written.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Save must not write an empty corpus")
	}
	b.Train([]byte("Subject: x\r\n\r\nqualcosa di interessante"), false)
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("corpus not written: %v", err)
	}
	// No temp file left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temporary file left behind")
	}
}
