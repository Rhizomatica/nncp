#!/bin/sh

texi=`mktemp`
cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS

`cat doc/news.texi`

@bye
EOF
makeinfo --plaintext -o NEWS $texi
rm -f $texi

texi=$(TMPDIR=doc mktemp)
cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle INSTALL

@include install.texi

@bye
EOF
makeinfo --plaintext -o INSTALL $texi
rm -f $texi
