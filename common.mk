GO ?= go
PREFIX ?= /usr/local

SENDMAIL ?= /usr/sbin/sendmail
CFGPATH ?= $(PREFIX)/etc/nncp.hjson
SPOOLPATH ?= /var/spool/nncp
LOGPATH ?= /var/spool/nncp/log

BINDIR = $(DESTDIR)$(PREFIX)/bin
INFODIR = $(DESTDIR)$(PREFIX)/info
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/nncp

MOD = go.cypherpunks.ru/nncp/v5

LDFLAGS = \
	-X $(MOD).Version=$(VERSION) \
	-X $(MOD).DefaultCfgPath=$(CFGPATH) \
	-X $(MOD).DefaultSendmailPath=$(SENDMAIL) \
	-X $(MOD).DefaultSpoolPath=$(SPOOLPATH) \
	-X $(MOD).DefaultLogPath=$(LOGPATH)

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

SRC := $(PWD)/src
BIN := $(PWD)/bin

all: $(ALL)

$(BIN):
	mkdir -p $(BIN)

$(ALL): $(BIN)
	cd $(SRC) ; GOPATH=$(GOPATH) $(GO) build -ldflags "$(LDFLAGS)" $(MOD)/cmd/$@
	mv $(SRC)/$@ $(BIN)

test:
	cd $(SRC) ; GOPATH=$(GOPATH) $(GO) test -failfast $(MOD)/...

clean:
	rm -rf $(BIN)

.PHONY: doc

doc:
	$(MAKE) -C doc

install: all doc
	mkdir -p $(BINDIR)
	(cd $(BIN) ; cp -f $(ALL) $(BINDIR))
	for e in $(ALL) ; do chmod 755 $(BINDIR)/$$e ; done
	mkdir -p $(INFODIR)
	cp -f doc/nncp.info $(INFODIR)
	chmod 644 $(INFODIR)/nncp.info
	mkdir -p $(DOCDIR)
	cp -f -L AUTHORS NEWS NEWS.RU README README.RU THANKS $(DOCDIR)
	chmod 644 $(DOCDIR)/*

install-strip: install
	for e in $(ALL) ; do strip $(BINDIR)/$$e ; done
