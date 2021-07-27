redo-ifchange \
    ../config \
    ../VERSION \
    *.texi \
    cfg/*.texi \
    cmd/*.texi \
    integration/*.texi \
    pedro.txt \
    pkt/*.texi \
    sp.plantuml.txt
. ../config
${MAKEINFO:-makeinfo} \
    -D "VERSION `cat ../VERSION`" \
    $MAKEINFO_OPTS \
    --set-customization-variable SECTION_NAME_IN_TITLE=1 \
    --set-customization-variable TREE_TRANSFORMATIONS=complete_tree_nodes_menus \
    --set-customization-variable CLOSE_QUOTE_SYMBOL=\" \
    --set-customization-variable OPEN_QUOTE_SYMBOL=\" \
    --output $3 index.texi
