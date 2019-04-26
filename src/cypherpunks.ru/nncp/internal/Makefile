chacha20:
	mkdir chacha20
	cp ../../../golang.org/x/crypto/internal/chacha20/* chacha20
	cp ../../../golang.org/x/crypto/internal/subtle/aliasing.go chacha20
	sed -i.bak 's/package subtle.*$$/package chacha20/' chacha20/aliasing.go
	sed -i.bak '/internal.subtle/d ; s/subtle\.//g' chacha20/chacha_generic.go
