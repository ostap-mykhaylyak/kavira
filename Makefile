APP      := kavira
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

# Installation layout (override on the command line if needed).
SBIN_DIR := /usr/sbin
CONF_DIR := /etc/$(APP)
LOG_DIR  := /var/log/$(APP)
LIB_DIR  := /var/lib/$(APP)
UNIT_DIR := /etc/systemd/system

.PHONY: all static static-arm64 release build test vet fmt clean install uninstall

all: static

build:
	go build -o bin/$(APP) ./cmd/$(APP)

static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP) ./cmd/$(APP)

static-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP)-arm64 ./cmd/$(APP)

release: static static-arm64

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin

install: static
	install -m 0755 bin/$(APP) $(SBIN_DIR)/$(APP)
	install -d -m 0750 $(CONF_DIR) $(CONF_DIR)/domains $(LOG_DIR) $(LIB_DIR) $(LIB_DIR)/queue
	install -d -m 0700 $(LIB_DIR)/dkim
	test -f $(CONF_DIR)/config.yaml || install -m 0640 internal/bootstrap/skel/etc/$(APP)/config.yaml $(CONF_DIR)/config.yaml
	test -f $(CONF_DIR)/domains/example.com.yaml.example || install -m 0640 internal/bootstrap/skel/etc/$(APP)/domains/example.com.yaml $(CONF_DIR)/domains/example.com.yaml.example
	install -m 0644 internal/bootstrap/$(APP).service $(UNIT_DIR)/$(APP).service
	@echo ""
	@echo "$(APP) $(VERSION) installed. Next steps:"
	@echo "  1. review $(CONF_DIR)/config.yaml"
	@echo "  2. cp $(CONF_DIR)/domains/example.com.yaml.example $(CONF_DIR)/domains/<your-domain>.yaml"
	@echo "  3. $(APP) check-config"
	@echo "  4. systemctl daemon-reload"
	@echo "  5. systemctl enable --now $(APP)"

uninstall:
	-systemctl disable --now $(APP) 2>/dev/null
	rm -f $(SBIN_DIR)/$(APP) $(UNIT_DIR)/$(APP).service
	@echo "config, logs and state left in place ($(CONF_DIR), $(LOG_DIR), $(LIB_DIR)); remove manually"
