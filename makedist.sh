#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/nncp-$release
repos="
    src/github.com/davecgh/go-xdr
    src/github.com/dustin/go-humanize
    src/github.com/flynn/noise
    src/github.com/minio/blake2b-simd
    src/golang.org/x/crypto
    src/golang.org/x/net
    src/golang.org/x/sys
    src/gopkg.in/check.v1
    src/gopkg.in/yaml.v2
"
for repo in $repos; do
    git clone $repo $tmp/nncp-$release/$repo
done
cd $tmp/nncp-$release
git checkout $release
git submodule update --init

cat > $tmp/includes <<EOF
golang.org/x/crypto/AUTHORS
golang.org/x/crypto/CONTRIBUTORS
golang.org/x/crypto/LICENSE
golang.org/x/crypto/PATENTS
golang.org/x/crypto/README
golang.org/x/crypto/blake2b
golang.org/x/crypto/blake2s
golang.org/x/crypto/chacha20poly1305
golang.org/x/crypto/curve25519
golang.org/x/crypto/ed25519
golang.org/x/crypto/hkdf
golang.org/x/crypto/nacl
golang.org/x/crypto/poly1305
golang.org/x/crypto/salsa20
golang.org/x/crypto/twofish
golang.org/x/net/AUTHORS
golang.org/x/net/CONTRIBUTORS
golang.org/x/net/LICENSE
golang.org/x/net/PATENTS
golang.org/x/net/README
golang.org/x/net/netutil
golang.org/x/sys/AUTHORS
golang.org/x/sys/CONTRIBUTORS
golang.org/x/sys/LICENSE
golang.org/x/sys/PATENTS
golang.org/x/sys/README
golang.org/x/sys/unix
EOF
tar cfCI - src $tmp/includes | tar xfC - $tmp
rm -fr src/golang.org
mv $tmp/golang.org src/
rm -fr $tmp/golang.org $tmp/includes

find src -name .travis.yml -delete
rm -fr src/github.com/davecgh/go-xdr/xdr
rm -fr src/github.com/gorhill/cronexpr/cronexpr src/github.com/gorhill/cronexpr/APLv2
rm -fr ports
rm makedist.sh

cat > doc/download.texi <<EOF
@node Tarballs
@section Prepared tarballs
You can obtain releases source code prepared tarballs on
@url{http://www.nncpgo.org/}.
EOF
make -C doc
./news_and_install.sh
rm -r doc/.well-known doc/nncp.html/.well-known news_and_install.sh

find . -name .git -type d | xargs rm -fr
find . -name .gitignore -delete
rm .gitmodules

cd ..
tar cvf nncp-"$release".tar nncp-"$release"
xz -9 nncp-"$release".tar
gpg --detach-sign --sign --local-user 0x2B25868E75A1A953 nncp-"$release".tar.xz
mv $tmp/nncp-"$release".tar.xz $tmp/nncp-"$release".tar.xz.sig $cur/doc/nncp.html/download

tarball=$cur/doc/nncp.html/download/nncp-"$release".tar.xz
size=$(( $(cat $tarball | wc -c) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
cat <<EOF
An entry for documentation:
@item @ref{Release $release, $release} @tab $size KiB
@tab @url{download/nncp-${release}.tar.xz, link} @url{download/nncp-${release}.tar.xz.sig, sign}
@tab @code{$hash}
EOF

cd $cur

cat <<EOF
Subject: NNCP $release release announcement

I am pleased to announce NNCP $release release availability!

NNCP (Node to Node copy) is a collection of utilities simplifying
secure store-and-forward files and mail exchanging.

This utilities are intended to help build up small size (dozens of
nodes) ad-hoc friend-to-friend (F2F) statically routed darknet networks
for fire-and-forget secure reliable files, file requests and Internet
mail transmission. All packets are integrity checked, end-to-end
encrypted (E2EE), explicitly authenticated by known participants public
keys. Onion encryption is applied to relayed packets. Each node acts
both as a client and server, can use push and poll behaviour model.

Out-of-box offline sneakernet/floppynet, dead drops and air-gapped
computers support. But online TCP daemon with full-duplex resumable data
transmission exists.

------------------------ >8 ------------------------

The main improvements for that release are:

$(git cat-file -p $release | sed -n '6,/^.*BEGIN/p' | sed '$d')

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
