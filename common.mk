PREFIX ?= /usr/local

SENDMAIL ?= /usr/sbin/sendmail
CFGPATH ?= $(PREFIX)/etc/nncp.yaml
SPOOLPATH ?= /var/spool/nncp
LOGPATH ?= /var/spool/nncp/log

BINDIR = $(DESTDIR)$(PREFIX)/bin
INFODIR = $(DESTDIR)$(PREFIX)/info
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/nncp

LDFLAGS = \
	-X cypherpunks.ru/nncp.Version=$(VERSION) \
	-X cypherpunks.ru/nncp.DefaultCfgPath=$(CFGPATH) \
	-X cypherpunks.ru/nncp.DefaultSendmailPath=$(SENDMAIL) \
	-X cypherpunks.ru/nncp.DefaultSpoolPath=$(SPOOLPATH) \
	-X cypherpunks.ru/nncp.DefaultLogPath=$(LOGPATH)

ALL = \
	nncp-bundle \
	nncp-call \
	nncp-caller \
	nncp-cfgenc \
	nncp-cfgmin \
	nncp-cfgnew \
	nncp-check \
	nncp-daemon \
	nncp-exec \
	nncp-file \
	nncp-freq \
	nncp-log \
	nncp-pkt \
	nncp-reass \
	nncp-rm \
	nncp-stat \
	nncp-toss \
	nncp-xfer

all: $(ALL)

src/cypherpunks.ru/nncp/internal/chacha20: src/golang.org/x/crypto/internal/chacha20 src/golang.org/x/crypto/internal/subtle
	$(MAKE) -C src/cypherpunks.ru/nncp/internal

nncp-bundle: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-bundle

nncp-call: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-call

nncp-caller: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-caller

nncp-cfgenc: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgenc

nncp-cfgmin: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgmin

nncp-cfgnew: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgnew

nncp-check: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-check

nncp-daemon: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-daemon

nncp-exec: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-exec

nncp-file: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-file

nncp-freq: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-freq

nncp-log: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-log

nncp-pkt: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-pkt

nncp-reass: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-reass

nncp-rm: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-rm

nncp-stat: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-stat

nncp-toss: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-toss

nncp-xfer: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-xfer

test: src/cypherpunks.ru/nncp/internal/chacha20
	GOPATH=$(GOPATH) go test -failfast cypherpunks.ru/nncp/...

clean:
	rm -f $(ALL)
	rm -fr src/cypherpunks.ru/nncp/internal/chacha20

.PHONY: doc

doc:
	$(MAKE) -C doc

install: all doc
	mkdir -p $(BINDIR)
	cp -f $(ALL) $(BINDIR)
	for e in $(ALL) ; do chmod 755 $(BINDIR)/$$e ; done
	mkdir -p $(INFODIR)
	cp -f doc/nncp.info $(INFODIR)
	chmod 644 $(INFODIR)/nncp.info
	mkdir -p $(DOCDIR)
	cp -f -L AUTHORS NEWS NEWS.RU README README.RU THANKS $(DOCDIR)
	chmod 644 $(DOCDIR)/*

install-strip: install
	for e in $(ALL) ; do strip $(BINDIR)/$$e ; done
