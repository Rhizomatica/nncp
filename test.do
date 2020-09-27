redo-ifchange config gopath module-name
. ./config
. ./gopath
mod=`cat module-name`
cd src
GOPATH=$GOPATH ${GO:-go} test -failfast $mod/...
