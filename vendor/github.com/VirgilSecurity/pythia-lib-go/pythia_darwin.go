package pythia

// #cgo CFLAGS:  -I${SRCDIR}/include/darwin -I${SRCDIR}/include/darwin/virgil/crypto/pythia
// #cgo LDFLAGS: -L${SRCDIR}/lib/darwin -lvirgil_crypto -lmbedcrypto -lstdc++ -lpythia -lrelic_s
import "C"
