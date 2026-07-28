#!/usr/bin/env make
# ═══════════════════════════════════════════════════════════════
#  Port Watcher v2 — Makefile
#  Author: RedVortex
#  License: MIT
# ═══════════════════════════════════════════════════════════════

SHELL := /bin/bash
SCRIPT_NAME := port-watcher
INSTALL_DIR := /usr/local/bin
INSTALL_DIR_LOCAL := $(HOME)/.local/bin
CONFIG_DIR := /etc/port-watcher
CONFIG_DIR_LOCAL := $(HOME)/.config/port-watcher

.PHONY: all install install-local uninstall test lint clean help

all: lint test

# ─── INSTALLATION ───

install:
	@echo "🔧 Installing Port Watcher v2..."
	@install -d $(DESTDIR)$(INSTALL_DIR)
	@install -m 755 src/$(SCRIPT_NAME).sh $(DESTDIR)$(INSTALL_DIR)/$(SCRIPT_NAME)
	@install -d $(DESTDIR)$(CONFIG_DIR)
	@install -m 644 config/ports.conf.example $(DESTDIR)$(CONFIG_DIR)/ports.conf.example
	@echo "✅ Installed to $(DESTDIR)$(INSTALL_DIR)/$(SCRIPT_NAME)"
	@echo "📝 Config example: $(DESTDIR)$(CONFIG_DIR)/ports.conf.example"
	@echo "ℹ️  Copy config: cp $(DESTDIR)$(CONFIG_DIR)/ports.conf.example ~/.config/port-watcher/ports.conf"

install-local:
	@echo "🔧 Installing Port Watcher v2 (user-local)..."
	@mkdir -p $(INSTALL_DIR_LOCAL)
	@install -m 755 src/$(SCRIPT_NAME).sh $(INSTALL_DIR_LOCAL)/$(SCRIPT_NAME)
	@mkdir -p $(CONFIG_DIR_LOCAL)
	@install -m 644 config/ports.conf.example $(CONFIG_DIR_LOCAL)/ports.conf.example
	@echo "✅ Installed to $(INSTALL_DIR_LOCAL)/$(SCRIPT_NAME)"
	@echo "📝 Config: $(CONFIG_DIR_LOCAL)/ports.conf.example"

uninstall:
	@echo "🗑️  Removing Port Watcher..."
	@rm -f $(DESTDIR)$(INSTALL_DIR)/$(SCRIPT_NAME)
	@echo "✅ Removed $(DESTDIR)$(INSTALL_DIR)/$(SCRIPT_NAME)"

# ─── TESTING ───

test:
	@echo "🧪 Running tests..."
	@if command -v bats &>/dev/null; then \
		bats tests/; \
	else \
		echo "⚠️  BATS not installed. Skipping tests."; \
		echo "   Install: npm install -g bats or apt install bats"; \
	fi

# ─── LINTING ───

lint:
	@echo "🔍 Running ShellCheck..."
	@if command -v shellcheck &>/dev/null; then \
		shellcheck src/*.sh; \
		echo "✅ ShellCheck passed"; \
	else \
		echo "⚠️  ShellCheck not installed. Skipping lint."; \
		echo "   Install: apt install shellcheck or brew install shellcheck"; \
	fi

# ─── CLEANUP ───

clean:
	@echo "🧹 Cleaning..."
	@rm -f port-watcher-report.html
	@rm -f *.log
	@echo "✅ Clean"

# ─── HELP ───

help:
	@echo "Port Watcher v2 — Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install        Install to system (requires sudo)"
	@echo "  install-local  Install to user-local (~/.local/bin)"
	@echo "  uninstall      Remove system installation"
	@echo "  test           Run BATS tests"
	@echo "  lint           Run ShellCheck"
	@echo "  clean          Remove generated files"
	@echo "  help           Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  DESTDIR=       Install prefix (default: empty)"
