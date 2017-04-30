#!/bin/sh

texi=`mktemp`

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS

`sed -n '5,$p' < doc/news.texi`

@bye
EOF
makeinfo --plaintext -o NEWS $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS.RU

@node Новости
@unnumbered Новости

`sed -n '3,$p' < doc/news.ru.texi | sed 's/^@subsection/@section/'`

@bye
EOF
makeinfo --plaintext -o NEWS.RU $texi

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

texi=`mktemp`

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle THANKS

`cat doc/thanks.texi`

@bye
EOF
makeinfo --plaintext -o THANKS $texi
rm -f $texi
