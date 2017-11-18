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
	nncp-file \
	nncp-freq \
	nncp-log \
	nncp-mail \
	nncp-pkt \
	nncp-reass \
	nncp-rm \
	nncp-stat \
	nncp-toss \
	nncp-xfer

all: $(ALL)

nncp-bundle:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-bundle

nncp-call:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-call

nncp-caller:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-caller

nncp-cfgenc:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgenc

nncp-cfgmin:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgmin

nncp-cfgnew:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-cfgnew

nncp-check:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-check

nncp-daemon:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-daemon

nncp-file:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-file

nncp-freq:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-freq

nncp-log:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-log

nncp-mail:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-mail

nncp-pkt:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-pkt

nncp-reass:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-reass

nncp-rm:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-rm

nncp-stat:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-stat

nncp-toss:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-toss

nncp-xfer:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-xfer

test:
	GOPATH=$(GOPATH) go test cypherpunks.ru/nncp/...

clean:
	rm -f $(ALL)

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
