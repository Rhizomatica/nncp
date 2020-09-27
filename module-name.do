redo-ifchange src/go.mod
sed -n 's/^module //p' < src/go.mod
