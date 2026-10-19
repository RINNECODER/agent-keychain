PREFIX ?= $(HOME)/.local

build:
	swift build -c release

install: build
	install -d $(PREFIX)/bin
	install -m 755 .build/release/agent-keychain $(PREFIX)/bin/agent-keychain

test:
	swift test

clean:
	rm -rf .build

.PHONY: build install test clean
