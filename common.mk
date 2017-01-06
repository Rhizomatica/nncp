.PHONY: doc

LDFLAGS = \
	-X cypherpunks.ru/nncp.Version=$(VERSION) \
	-X cypherpunks.ru/nncp.DefaultCfgPath=$(CFGPATH) \
	-X cypherpunks.ru/nncp.DefaultSendmailPath=$(SENDMAIL)

all: \
	nncp-call \
	nncp-check \
	nncp-daemon \
	nncp-file \
	nncp-freq \
	nncp-log \
	nncp-mail \
	nncp-newnode \
	nncp-pkt \
	nncp-stat \
	nncp-toss \
	nncp-xfer

nncp-call:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/nncp/cmd/nncp-call

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
	rm -f \
		nncp-call \
		nncp-daemon \
		nncp-file \
		nncp-freq \
		nncp-log \
		nncp-mail \
		nncp-newnode \
		nncp-pkt \
		nncp-stat \
		nncp-toss \
		nncp-xfer

doc:
	$(MAKE) -C doc
