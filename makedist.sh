#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/nncp-$release
cd $tmp/nncp-$release
git checkout v$release
redo module-name VERSION
rm -r .redo
mod_name=`cat module-name`
rm -fr .git

mv src src.orig
mkdir -p src/$mod_name
mv src.orig/* src/$mod_name
rmdir src.orig

mods="
github.com/davecgh/go-xdr
github.com/dustin/go-humanize
github.com/flynn/noise
github.com/gorhill/cronexpr
github.com/hjson/hjson-go
github.com/klauspost/compress
go.cypherpunks.ru/balloon
golang.org/x/crypto
golang.org/x/net
golang.org/x/sys
golang.org/x/term
"
for mod in $mods; do
    mod_path=$(sed -n "s# // indirect## ; s#^	\($mod\) \(.*\)\$#\1@\2#p" src/$mod_name/go.mod)
    [ -n "$mod_path" ] || {
        mod_path=$(sed -n "s#\($mod\) \([^/]*\) .*\$#\1@\2#p" src/$mod_name/go.sum)
    }
    [ -n "$mod_path" ]
    mkdir -p src/$mod
    ( cd $GOPATH/pkg/mod/$mod_path ; tar cf - --exclude ".git*" * ) | tar xfC - src/$mod
    chmod -R +w src/$mod
done

cat > $tmp/includes <<EOF
golang.org/x/crypto/AUTHORS
golang.org/x/crypto/blake2b
golang.org/x/crypto/blake2s
golang.org/x/crypto/chacha20
golang.org/x/crypto/chacha20poly1305
golang.org/x/crypto/CONTRIBUTORS
golang.org/x/crypto/curve25519
golang.org/x/crypto/ed25519
golang.org/x/crypto/go.mod
golang.org/x/crypto/go.sum
golang.org/x/crypto/internal/subtle
golang.org/x/crypto/LICENSE
golang.org/x/crypto/nacl
golang.org/x/crypto/PATENTS
golang.org/x/crypto/poly1305
golang.org/x/crypto/README.md
golang.org/x/crypto/salsa20
golang.org/x/crypto/ssh/terminal
golang.org/x/net/AUTHORS
golang.org/x/net/CONTRIBUTORS
golang.org/x/net/go.mod
golang.org/x/net/go.sum
golang.org/x/net/LICENSE
golang.org/x/net/netutil
golang.org/x/net/PATENTS
golang.org/x/net/README.md
golang.org/x/sys/AUTHORS
golang.org/x/sys/CONTRIBUTORS
golang.org/x/sys/cpu
golang.org/x/sys/go.mod
golang.org/x/sys/internal/unsafeheader
golang.org/x/sys/LICENSE
golang.org/x/sys/PATENTS
golang.org/x/sys/README.md
golang.org/x/sys/unix
golang.org/x/term
EOF
tar cfCI - src $tmp/includes | tar xfC - $tmp
rm -fr src/golang.org $tmp/includes
mv $tmp/golang.org src

cat > $tmp/includes <<EOF
compress/compressible.go
compress/fse
compress/huff0
compress/LICENSE
compress/README.md
compress/zstd
EOF
cat > $tmp/excludes <<EOF
*testdata*
*_test.go
snappy.go
EOF
tar cfCIX - src/github.com/klauspost $tmp/includes $tmp/excludes | tar xfC - $tmp
rm -fr src/github.com/klauspost/compress $tmp/includes $tmp/excludes
mv $tmp/compress src/github.com/klauspost

find src -name .travis.yml -delete
rm -fr src/github.com/davecgh/go-xdr/xdr
rm -r src/github.com/flynn/noise/vector*
rm src/github.com/hjson/hjson-go/build_release.sh
rm src/github.com/gorhill/cronexpr/APLv2
rm -fr ports
find . -name .gitignore -delete
rm makedist.sh module-name.do VERSION.do

mkdir contrib
cp ~/work/redo/minimal/do contrib/do
echo echo GOPATH=\`pwd\` > gopath.do

perl -p -i -e "s#src/#src/$mod_name/#g" bin/default.do

cat > doc/download.texi <<EOF
@node Tarballs
@section Prepared tarballs
You can obtain releases source code prepared tarballs on
@url{http://www.nncpgo.org/}.
EOF
perl -i -ne 'print unless /include pedro/' doc/index.texi doc/about.ru.texi
perl -p -i -e 's/^(.verbatiminclude) .*$/$1 PUBKEY.asc/g' doc/integrity.texi
mv doc/.well-known/openpgpkey/hu/i4cdqgcarfjdjnba6y4jnf498asg8c6p.asc PUBKEY.asc
ln -s ../PUBKEY.asc doc
redo doc

########################################################################
# Supplementary files autogeneration
########################################################################
texi=$(TMPDIR=doc mktemp)

mkinfo() {
    ${MAKEINFO:-makeinfo} --plaintext \
        --set-customization-variable CLOSE_QUOTE_SYMBOL=\" \
        --set-customization-variable OPEN_QUOTE_SYMBOL=\" \
        -D "VERSION `cat VERSION`" $@
}

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS
@node News
@unnumbered News
`sed -n '5,$p' < doc/news.texi`
@bye
EOF
mkinfo --output NEWS $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle NEWS.RU
@node Новости
@unnumbered Новости
`sed -n '3,$p' < doc/news.ru.texi | sed 's/^@subsection/@section/'`
@bye
EOF
mkinfo --output NEWS.RU $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle INSTALL
@include install.texi
@bye
EOF
mkinfo --output INSTALL $texi

cat > $texi <<EOF
\input texinfo
@documentencoding UTF-8
@settitle THANKS
`cat doc/thanks.texi`
@bye
EOF
mkinfo --output THANKS $texi

rm -f $texi
rm -r doc/.well-known doc/nncp.html/.well-known

########################################################################

rm -r .redo doc/.redo
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;
find . -type f -name "*.sh" -exec chmod 755 {} \;
chmod 755 contrib/do

cd ..
tar cvf nncp-"$release".tar --uid=0 --gid=0 --numeric-owner nncp-"$release"
xz -9v nncp-"$release".tar
gpg --detach-sign --sign --local-user releases@nncpgo.org nncp-"$release".tar.xz
mv -v $tmp/nncp-"$release".tar.xz $tmp/nncp-"$release".tar.xz.sig $cur/doc/download

tarball=$cur/doc/download/nncp-"$release".tar.xz
size=$(( $(stat -f %z $tarball) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
release_date=$(date "+%Y-%m-%d")

cat <<EOF
An entry for documentation:
@item @ref{Release $release, $release} @tab $release_date @tab $size KiB
@tab @url{download/nncp-${release}.tar.xz, link} @url{download/nncp-${release}.tar.xz.sig, sign}
@tab @code{$hash}
EOF

cd $cur

cat <<EOF
Subject: [EN] NNCP $release release announcement

I am pleased to announce NNCP $release release availability!

NNCP (Node to Node copy) is a collection of utilities simplifying
secure store-and-forward files and mail exchanging.

This utilities are intended to help build up small size (dozens of
nodes) ad-hoc friend-to-friend (F2F) statically routed darknet
delay-tolerant networks for fire-and-forget secure reliable files, file
requests, Internet mail and commands transmission. All packets are
integrity checked, end-to-end encrypted (E2EE), explicitly authenticated
by known participants public keys. Onion encryption is applied to
relayed packets. Each node acts both as a client and server, can use
push and poll behaviour model.

Out-of-box offline sneakernet/floppynet, dead drops, sequential and
append-only CD-ROM/tape storages, air-gapped computers support. But
online TCP daemon with full-duplex resumable data transmission exists.

------------------------ >8 ------------------------

The main improvements for that release are:

$(git cat-file -p v$release | sed -n '6,/^.*BEGIN/p' | sed '$d')

------------------------ >8 ------------------------

NNCP's home page is: http://www.nncpgo.org/

Source code and its signature for that version can be found here:

    http://www.nncpgo.org/download/nncp-${release}.tar.xz ($size KiB)
    http://www.nncpgo.org/download/nncp-${release}.tar.xz.sig

SHA256 hash: $hash
GPG key ID: 0x2B25868E75A1A953 NNCP releases <releases@nncpgo.org>
Fingerprint: 92C2 F0AE FE73 208E 46BF  F3DE 2B25 868E 75A1 A953

Please send questions regarding the use of NNCP, bug reports and patches
to mailing list: https://lists.cypherpunks.ru/pipermail/nncp-devel/
EOF

cat <<EOF
Subject: [RU] Состоялся релиз NNCP $release

Я рад сообщить о выходе релиза NNCP $release!

NNCP (Node to Node copy) это набор утилит упрощающий безопасный обмен
файлами и почтой в режиме сохранить-и-переслать.

Эти утилиты предназначены помочь с построением одноранговых устойчивых к
разрывам сетей небольшого размера (дюжины узлов), в режиме друг-к-другу
(F2F) со статической маршрутизацией для безопасной надёжной передачи
файлов, запросов на передачу файлов, Интернет почты и команд по принципу
выстрелил-и-забыл. Все пакеты проверяются на целостность, шифруются по
принципу точка-точка (E2EE), аутентифицируются известными публичными
ключами участников. Луковичное (onion) шифрование применяется ко всем
ретранслируемым пакетам. Каждый узел выступает одновременно в роли
клиента и сервера, может использовать как push, так и poll модель
поведения.

Поддержка из коробки offline флоппинета, тайников для сброса информации
(dead drop), последовательных и только-для-записи CD-ROM/ленточных
хранилищ, компьютеров с "воздушным зазором" (air-gap). Но также
существует и online TCP демон с полнодуплексной возобновляемой передачей
данных.

------------------------ >8 ------------------------

Основные усовершенствования в этом релизе:

$(git cat-file -p v$release | sed -n '6,/^.*BEGIN/p' | sed '$d')

------------------------ >8 ------------------------

Домашняя страница NNCP: http://www.nncpgo.org/
Коротко об утилитах: http://www.nncpgo.org/Ob-utilitakh.html

Исходный код и его подпись для этой версии находятся здесь:

    http://www.nncpgo.org/download/nncp-${release}.tar.xz ($size KiB)
    http://www.nncpgo.org/download/nncp-${release}.tar.xz.sig

SHA256 хэш: $hash
Идентификатор GPG ключа: 0x2B25868E75A1A953 NNCP releases <releases@nncpgo.org>
Отпечаток: 92C2 F0AE FE73 208E 46BF  F3DE 2B25 868E 75A1 A953

Пожалуйста, все вопросы касающиеся использования NNCP, отчёты об ошибках
и патчи отправляйте в nncp-devel почтовую рассылку:
https://lists.cypherpunks.ru/pipermail/nncp-devel/
EOF
