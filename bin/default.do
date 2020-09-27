cd ..
redo-ifchange config gopath module-name
. ./config
. ./gopath
mod=`cat module-name`
redo-ifchange src/*.go src/cmd/$1/*.go
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultCfgPath=$CFGPATH"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultSendmailPath=$SENDMAIL"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultSpoolPath=$SPOOLPATH"
GO_LDFLAGS="$GO_LDFLAGS -X $mod.DefaultLogPath=$LOGPATH"
cd src
GOPATH=$GOPATH ${GO:-go} build -o ../bin/$3 -ldflags "$GO_LDFLAGS" $mod/cmd/$1
