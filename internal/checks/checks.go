// Package checks implements kavira's diagnostic commands.
//
// The split is deliberate:
//
//   - audit inspects what is on this machine — the configuration and
//     the filesystem — and never touches the network, so it is safe to
//     run anywhere, including on a box that is not yet in production.
//   - security-check exercises the live deployment: DNS records, an
//     actual open-relay attempt against the running server, TLS,
//     reverse DNS, blacklists. It needs the daemon running and the
//     domains published.
//   - container-check answers one question: does this containerized
//     deployment look, from the outside, like a server on the metal?
//
// Every check reports a status and, when something is wrong, what to
// do about it. The exit code is what a monitoring system reads.
package checks

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Status is the outcome of a single check.
type Status int

const (
	// Pass means the check found nothing wrong.
	Pass Status = iota
	// Warn means something deserves attention but does not break
	// mail flow or security.
	Warn
	// Fail means a real problem: mail is broken, or the server is
	// exposed.
	Fail
	// Skip means the check could not run (feature disabled, no data).
	Skip
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	default:
		return "SKIP"
	}
}

// Result is one finding.
type Result struct {
	// Section groups related checks in the output.
	Section string
	// Name identifies the check.
	Name string
	// Status is the outcome.
	Status Status
	// Detail explains what was found.
	Detail string
	// Fix is the suggested remedy, shown only for Warn and Fail.
	Fix string
}

// Report collects results.
type Report struct {
	Results []Result
}

// Add records a finding.
func (r *Report) Add(section, name string, status Status, detail, fix string) {
	r.Results = append(r.Results, Result{
		Section: section, Name: name, Status: status, Detail: detail, Fix: fix,
	})
}

// Pass, Warn, Fail and Skip are shorthands for Add.
func (r *Report) Pass(section, name, detail string) {
	r.Add(section, name, Pass, detail, "")
}
func (r *Report) Warn(section, name, detail, fix string) {
	r.Add(section, name, Warn, detail, fix)
}
func (r *Report) Fail(section, name, detail, fix string) {
	r.Add(section, name, Fail, detail, fix)
}
func (r *Report) Skip(section, name, detail string) {
	r.Add(section, name, Skip, detail, "")
}

// Counts totals the results by status.
func (r *Report) Counts() (pass, warn, fail, skip int) {
	for _, res := range r.Results {
		switch res.Status {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		case Skip:
			skip++
		}
	}
	return
}

// ExitCode is 0 when nothing failed, 1 when something did. Warnings
// alone do not fail the run: a monitoring system should page on Fail,
// not on a certificate that expires in ten days.
func (r *Report) ExitCode() int {
	if _, _, fail, _ := r.Counts(); fail > 0 {
		return 1
	}
	return 0
}

// Print renders the report. Sections keep their first-seen order, so
// the output reads in the order the checks were written.
func (r *Report) Print(w io.Writer, title string) {
	fmt.Fprintf(w, "%s\n%s\n\n", title, strings.Repeat("=", len(title)))

	var order []string
	bySection := map[string][]Result{}
	for _, res := range r.Results {
		if _, seen := bySection[res.Section]; !seen {
			order = append(order, res.Section)
		}
		bySection[res.Section] = append(bySection[res.Section], res)
	}

	for _, section := range order {
		fmt.Fprintf(w, "%s\n%s\n", section, strings.Repeat("-", len(section)))
		for _, res := range bySection[section] {
			fmt.Fprintf(w, "  [%s] %s", res.Status, res.Name)
			if res.Detail != "" {
				fmt.Fprintf(w, ": %s", res.Detail)
			}
			fmt.Fprintln(w)
			if res.Fix != "" && (res.Status == Warn || res.Status == Fail) {
				fmt.Fprintf(w, "         fix: %s\n", res.Fix)
			}
		}
		fmt.Fprintln(w)
	}

	pass, warn, fail, skip := r.Counts()
	fmt.Fprintf(w, "%d passed, %d warnings, %d failures, %d skipped\n", pass, warn, fail, skip)
	if fail > 0 {
		fmt.Fprintln(w, "\nFailures need attention: mail delivery or security is affected.")
	}
}

// sortedDomains returns domain names in a stable order.
func sortedDomains(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
