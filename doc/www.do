html=nncp.html
rm -fr $html
redo $html
cp -a .well-known $html/
cp -a download $html/
cp ../PUBKEY-* $html/
(
    cd $html/download
    export ATOM_ID="e33cb83e-bf33-46f8-b9b1-6115f46e1218"
    export NAME=NNCP
    export BASE_URL=http://www.nncpgo.org/download
    export AUTHOR_EMAIL=releases@nncpgo.org
    ~/work/releases-feed/releases.atom.zsh
)
perl -i -npe 'print "<link rel=\"alternate\" title=\"Releases\" href=\"download/releases.atom\" type=\"application/atom+xml\">\n" if /^<\/head>/' $html/Tarballs.html
find nncp.html -type d -exec chmod 755 {} +
find nncp.html -type f -exec chmod 644 {} +
