# $FreeBSD$

PORTNAME=	nncp
PORTVERSION=	0.7
CATEGORIES=	net
MASTER_SITES=	http://www.nncpgo.org/download/ \
		http://sourceforge.net/projects/nncp/files/

MAINTAINER=	stargrave@stargrave.org
COMMENT=	Utilities for secure store-and-forward files and mail exchanging

LICENSE=	GPLv3+
LICENSE_FILE=	${WRKSRC}/COPYING

BUILD_DEPENDS=	go:lang/go

USES=		tar:xz
MAKEFILE=	BSDmakefile

USE_RC_SUBR=	nncp-caller nncp-daemon nncp-toss
REQUIRE=	DAEMON

SUB_FILES=	pkg-message pkg-install pkg-deinstall nncp.newsyslog.conf.sample

PORTDOCS=	AUTHORS NEWS README README.RU THANKS
INFO=		nncp
INSTALL_TARGET=	install-strip

PLIST_FILES=	bin/nncp-call \
		bin/nncp-caller \
		bin/nncp-check \
		bin/nncp-daemon \
		bin/nncp-file \
		bin/nncp-freq \
		bin/nncp-log \
		bin/nncp-mail \
		bin/nncp-mincfg \
		bin/nncp-newcfg \
		bin/nncp-pkt \
		bin/nncp-reass \
		bin/nncp-rm \
		bin/nncp-stat \
		bin/nncp-toss \
		bin/nncp-xfer \
		"@sample etc/newsyslog.conf.d/nncp.conf.sample"

post-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d
	${INSTALL_DATA} ${WRKDIR}/nncp.newsyslog.conf.sample ${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d/nncp.conf.sample

.include <bsd.port.mk>
