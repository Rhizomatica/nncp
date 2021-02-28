redo-ifchange ../config ../VERSION *.texi sp.plantuml.txt pedro.txt
. ../config
${MAKEINFO:-makeinfo} \
    -D "VERSION `cat ../VERSION`" \
    $MAKEINFO_OPTS \
    --set-customization-variable CLOSE_QUOTE_SYMBOL=\" \
    --set-customization-variable OPEN_QUOTE_SYMBOL=\" \
    --output $3 index.texi
