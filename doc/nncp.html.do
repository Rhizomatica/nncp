redo-ifchange makeinfo.rc
MAKEINFO_OPTS="$MAKEINFO_OPTS --html"
MAKEINFO_OPTS="$MAKEINFO_OPTS --set-customization-variable NO_CSS=1"
MAKEINFO_OPTS="$MAKEINFO_OPTS --set-customization-variable FORMAT_MENU=menu"
MAKEINFO_OPTS="$MAKEINFO_OPTS --set-customization-variable DATE_IN_HEADER=1"
MAKEINFO_OPTS="$MAKEINFO_OPTS" . makeinfo.rc
