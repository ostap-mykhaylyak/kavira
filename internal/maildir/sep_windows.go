//go:build windows

package maildir

// infoChar replaces the standard ':' separator, which NTFS reserves
// for alternate data streams. Development happens on Windows,
// deployment on Linux; the on-disk names are not portable between the
// two, which is acceptable since a Maildir is never moved across
// platforms mid-flight.
const infoChar = ";"
