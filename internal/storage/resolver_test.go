package storage

import (
	"testing"

	"github.com/ostap-mykhaylyak/kavira/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Domains: []config.Domain{
			{Name: "example.com"},
			{Name: "ostap.dev", Storage: config.Storage{
				Type: config.StorageSystemUser, User: "ostap",
				Home: "/home/ostap", Maildir: "{home}/mail",
			}},
		},
		Users: []config.User{
			{Email: "admin@example.com", Maildir: "/var/mail/example.com/admin"},
		},
	}
}

func TestResolveVirtual(t *testing.T) {
	mb, ok := Resolve(testConfig(), "Admin@Example.COM")
	if !ok {
		t.Fatal("want resolved")
	}
	if mb.Dir != "/var/mail/example.com/admin" || mb.Email != "admin@example.com" {
		t.Errorf("mailbox = %+v", mb)
	}
}

func TestResolveSystemUser(t *testing.T) {
	mb, ok := Resolve(testConfig(), "ostap@ostap.dev")
	if !ok {
		t.Fatal("want resolved")
	}
	if mb.Dir != "/home/ostap/mail" {
		t.Errorf("dir = %q", mb.Dir)
	}
	if _, ok := Resolve(testConfig(), "other@ostap.dev"); ok {
		t.Error("system_user domain must only expose its bound account")
	}
}

func TestResolveUnknown(t *testing.T) {
	if _, ok := Resolve(testConfig(), "nobody@example.com"); ok {
		t.Error("unknown virtual user must not resolve")
	}
	if _, ok := Resolve(testConfig(), "a@elsewhere.org"); ok {
		t.Error("foreign domain must not resolve")
	}
	if _, ok := Resolve(testConfig(), "not-an-address"); ok {
		t.Error("malformed address must not resolve")
	}
}
