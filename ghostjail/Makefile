GO      ?= go
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -D_GNU_SOURCE -fstack-protector-strong
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
LIBDIR  ?= $(PREFIX)/lib

BIN     = bin/ghostjail
PRELOAD = bin/libghostjail.so

.PHONY: all test unit integration vet install uninstall clean

all: $(BIN) $(PRELOAD)

# Static, cgo-free binary: it must start inside fresh namespaces.
$(BIN): $(shell find cmd internal -name '*.go') go.mod go.sum
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w' -o $@ ./cmd/ghostjail

$(PRELOAD): preload/libghostjail.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@ -ldl

vet:
	$(GO) vet ./...

unit:
	$(GO) test ./...

integration: all
	python3 -I tests/test_ghostjail.py

test: vet unit integration

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)/ghostjail
	install -m 755 $(PRELOAD) $(DESTDIR)$(LIBDIR)/libghostjail.so

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/ghostjail $(DESTDIR)$(LIBDIR)/libghostjail.so

clean:
	rm -rf bin
