.PHONY: doc

CFGPATH ?= /usr/local/etc/nncp.yaml
SENDMAIL ?= /usr/sbin/sendmail
LDFLAGS = \
	-X cypherpunks.ru/nncp.Version=$(VERSION) \
	-X cypherpunks.ru/nncp.DefaultCfgPath=$(CFGPATH) \
	-X cypherpunks.ru/nncp.DefaultSendmailPath=$(SENDMAIL)
PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin
INFODIR = $(DESTDIR)$(PREFIX)/info
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/nncp
ALL = \
	nncp-mail \
	nncp-call \
	nncp-caller \
	nncp-check \
	nncp-daemon \
	nncp-file \
	nncp-freq \
	nncp-log \
	nncp-newnode \
	nncp-pkt \
	nncp-stat \
	nncp-toss \
	nncp-xfer

all: $(ALL)

nncp-call:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-call

nncp-caller:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-caller

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

nncp-newnode:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-newnode

nncp-pkt:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-pkt

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
	cp -f -L AUTHORS README THANKS $(DOCDIR)
	chmod 644 $(DOCDIR)/*

install-strip: install
	for e in $(ALL) ; do strip $(BINDIR)/$$e ; done
