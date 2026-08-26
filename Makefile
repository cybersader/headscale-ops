.PHONY: build fmt-check script-check test vet check install clean

GO ?= go
VERSION ?= dev
REVISION ?= $(shell git rev-parse --verify HEAD 2>/dev/null || printf unknown)
PREFIX ?= $(HOME)/.local
LDFLAGS = -s -w -X main.buildVersion=$(VERSION) -X main.buildRevision=$(REVISION)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o headscale-ops .

fmt-check:
	@unformatted="$$(gofmt -l *.go)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'gofmt required for:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

script-check:
	bash -n scripts/publish-release.sh

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

check: fmt-check script-check vet test

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 headscale-ops "$(DESTDIR)$(PREFIX)/bin/headscale-ops"

clean:
	rm -f headscale-ops
