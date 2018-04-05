package pythia

// #cgo CFLAGS:  -I${SRCDIR}/include/linux -I${SRCDIR}/include/linux/virgil/crypto/pythia
// #cgo LDFLAGS: -L${SRCDIR}/lib/linux -lvirgil_crypto -lmbedcrypto -lstdc++ -lpythia -lrelic_s
import "C"
