CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -D_GNU_SOURCE -fstack-protector-strong
LDFLAGS ?= 
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib

SRCDIR = src
OBJDIR = obj
BIN = bin

TARGET = $(BIN)/tzspoof
PRELOAD_LIB = $(BIN)/libtzspoof.so

SOURCES = $(SRCDIR)/main.c $(SRCDIR)/spoof.c $(SRCDIR)/tzutil.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean test install uninstall help

all: $(TARGET) $(PRELOAD_LIB)

$(BIN):
	mkdir -p $(BIN)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS) | $(BIN)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

$(PRELOAD_LIB): $(SRCDIR)/preload.c | $(BIN)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@ -ldl

clean:
	rm -rf $(OBJDIR) $(BIN)

test: all
	@echo "Running tzspoof validation suite..."
	@./$(TARGET) -v
	@echo "Test 1: UTC date command"
	@./$(TARGET) -q UTC date | grep -i "UTC" >/dev/null && echo "  [PASS] UTC date check"
	@echo "Test 2: Tokyo timezone resolution and alias"
	@./$(TARGET) -q tokyo date | grep -i "JST" >/dev/null && echo "  [PASS] Tokyo JST check"
	@echo "Test 3: London timezone resolution and alias"
	@./$(TARGET) -q london date | grep -E "GMT|BST" >/dev/null && echo "  [PASS] London GMT/BST check"
	@echo "Test 4: Node.js /etc/localtime resolution"
	@if command -v node >/dev/null 2>&1; then \
		./$(TARGET) -q tokyo node -e "if (Intl.DateTimeFormat().resolvedOptions().timeZone !== 'Asia/Tokyo') process.exit(1);" && echo "  [PASS] Node.js timezone check"; \
	fi
	@echo "Test 5: Python datetime zone check"
	@if command -v python3 >/dev/null 2>&1; then \
		./$(TARGET) -q ny python3 -c "import time; assert 'EST' in time.tzname or 'EDT' in time.tzname" && echo "  [PASS] Python tzname check"; \
	fi
	@echo "Test 6: OpenSSH configuration parsing & UID check"
	@if command -v ssh >/dev/null 2>&1; then \
		./$(TARGET) -q tokyo ssh -G localhost >/dev/null 2>&1 && echo "  [PASS] OpenSSH config check"; \
	fi
	@echo "Test 7: Hermetic namespace regression tests"
	@python3 -I tests/test_tzspoof.py
	@echo "All tests passed successfully!"

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/tzspoof
	install -m 755 $(PRELOAD_LIB) $(DESTDIR)$(LIBDIR)/libtzspoof.so
	@echo "tzspoof installed to $(DESTDIR)$(BINDIR)/tzspoof"
	@echo "libtzspoof.so installed to $(DESTDIR)$(LIBDIR)/libtzspoof.so"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/tzspoof
	rm -f $(DESTDIR)$(LIBDIR)/libtzspoof.so
	@echo "tzspoof uninstalled."

help:
	@echo "Targets:"
	@echo "  all       : Build tzspoof and libtzspoof.so (default)"
	@echo "  test      : Run validation tests"
	@echo "  clean     : Remove compiled objects and binaries"
	@echo "  install   : Install tzspoof to PREFIX ($(PREFIX))"
	@echo "  uninstall : Remove installed files from PREFIX"
