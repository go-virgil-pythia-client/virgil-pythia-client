package pythia

// #include "virgil_pythia_c.h"
import "C"
import (
	"C"
	"fmt"

	"github.com/pkg/errors"
)

var (
	BN_SIZE = int(C.PYTHIA_BN_BUF_SIZE)
	G1_SIZE = int(C.PYTHIA_G1_BUF_SIZE)
	G2_SIZE = int(C.PYTHIA_G2_BUF_SIZE)
	GT_SIZE = int(C.PYTHIA_GT_BUF_SIZE)
)

type Pythia struct {
}

func New() *Pythia {
	return &Pythia{}
}

// Blind turns password into a pseudo-random string.
func (p *Pythia) Blind(password []byte) (blindedPassword, blindingSecret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	blindedPasswordBuf := NewBuf(G1_SIZE)
	defer blindedPasswordBuf.Close()

	blindingSecretBuf := NewBuf(BN_SIZE)
	defer blindingSecretBuf.Close()

	passwordBuf := NewBufWithData(password)
	defer passwordBuf.Close()

	pErr := C.virgil_pythia_blind(passwordBuf.inBuf, blindedPasswordBuf.inBuf, blindingSecretBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	return blindedPasswordBuf.GetData(), blindingSecretBuf.GetData(), nil
}

// Deblind unmasks value y with previously returned secret from Blind()
func (p *Pythia) Deblind(transformedPassword []byte, blindingSecret []byte) (deblindedPassword []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	transformedPasswordBuf := NewBufWithData(transformedPassword)
	defer transformedPasswordBuf.Close()
	secretBuf := NewBufWithData(blindingSecret)
	defer secretBuf.Close()

	deblindedBuf := NewBuf(GT_SIZE)
	defer deblindedBuf.Close()
	pErr := C.virgil_pythia_deblind(transformedPasswordBuf.inBuf, secretBuf.inBuf, deblindedBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	return deblindedBuf.GetData(), nil
}

// Transform turns blinded password into cryptographically strong value.
func (p *Pythia) Transform(blindedPassword, transformationKeyID, tweak, pythiaSecret, pythiaScopeSecret []byte) (transformedPassword, transformationPrivateKey, transformedTweak []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	transformationKeyIDBuf := NewBufWithData(transformationKeyID)
	defer transformationKeyIDBuf.Close()
	tweakBuf := NewBufWithData(tweak)
	defer tweakBuf.Close()
	blindedPasswordBuf := NewBufWithData(blindedPassword)
	defer blindedPasswordBuf.Close()
	pythiaSecretBuf := NewBufWithData(pythiaSecret)
	defer pythiaSecretBuf.Close()
	pythiaScopeSecretBuf := NewBufWithData(pythiaScopeSecret)
	defer pythiaScopeSecretBuf.Close()

	transformedPasswordBuf := NewBuf(GT_SIZE)
	defer transformedPasswordBuf.Close()
	transformationPrivateKeyBuf := NewBuf(BN_SIZE)
	defer transformationPrivateKeyBuf.Close()
	transformedTweakBuf := NewBuf(G2_SIZE)
	defer transformedTweakBuf.Close()

	pErr := C.virgil_pythia_transform(blindedPasswordBuf.inBuf, transformationKeyIDBuf.inBuf, tweakBuf.inBuf, pythiaSecretBuf.inBuf, pythiaScopeSecretBuf.inBuf, transformedPasswordBuf.inBuf, transformationPrivateKeyBuf.inBuf, transformedTweakBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	return transformedPasswordBuf.GetData(), transformationPrivateKeyBuf.GetData(), transformedTweakBuf.GetData(), nil
}

// Prove proves that server possesses secret values that are used to protect password
func (p *Pythia) Prove(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey []byte) (transformationPublicKey, proofValueC, proofValueU []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	blindedPasswordBuf := NewBufWithData(blindedPassword)
	defer blindedPasswordBuf.Close()

	transformedTweakBuf := NewBufWithData(transformedTweak)
	defer transformedTweakBuf.Close()

	transformationPrivateKeyBuf := NewBufWithData(transformationPrivateKey)
	defer transformationPrivateKeyBuf.Close()

	transformedPasswordBuf := NewBufWithData(transformedPassword)
	defer transformedPasswordBuf.Close()

	transformationPublicKeyBuf := NewBuf(G1_SIZE)
	defer transformationPublicKeyBuf.Close()

	proofValueCBuf := NewBuf(BN_SIZE)
	defer proofValueCBuf.Close()

	proofValueUBuf := NewBuf(BN_SIZE)
	defer proofValueUBuf.Close()

	pErr := C.virgil_pythia_prove(transformedPasswordBuf.inBuf, blindedPasswordBuf.inBuf, transformedTweakBuf.inBuf, transformationPrivateKeyBuf.inBuf, transformationPublicKeyBuf.inBuf, proofValueCBuf.inBuf, proofValueUBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	transformationPublicKey = transformationPublicKeyBuf.GetData()
	proofValueC = proofValueCBuf.GetData()
	proofValueU = proofValueUBuf.GetData()
	return
}

//Verify The protocol enables a client to verify that
//the output of Transform() is correct, assuming the client has
//previously stored p. The server accompanies the output
//y of the Transform() with a zero-knowledge proof (c, u) of correctness
func (p *Pythia) Verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU []byte) (err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	blindedPasswordBuf := NewBufWithData(blindedPassword)
	defer blindedPasswordBuf.Close()

	tweakBuf := NewBufWithData(tweak)
	defer tweakBuf.Close()

	transformedPasswordBuf := NewBufWithData(transformedPassword)
	defer transformedPasswordBuf.Close()

	transformationPublicKeyBuf := NewBufWithData(transformationPublicKey)
	defer transformationPublicKeyBuf.Close()

	proofValueCBuf := NewBufWithData(proofValueC)
	defer proofValueCBuf.Close()

	proofValueUBuf := NewBufWithData(proofValueU)
	defer proofValueUBuf.Close()

	var verified C.int

	pErr := C.virgil_pythia_verify(transformedPasswordBuf.inBuf, blindedPasswordBuf.inBuf, tweakBuf.inBuf, transformationPublicKeyBuf.inBuf, proofValueCBuf.inBuf, proofValueUBuf.inBuf, &verified)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	if int(verified) != 1 {
		return errors.New("Verification failed")
	}

	return nil
}

// GetPasswordUpdateToken generates token that can update protected passwords from the combination of (old) w1, msk1, ssk1 to (new) w2, msk2, ssk2
func (p *Pythia) GetPasswordUpdateToken(previousTransformationKeyID, previousPythiaSecret, previousPythiaScopeSecret, newTransformationKeyID, newPythiaSecret, newPythiaScopeSecret []byte) (passwordUpdateToken, updatedTransformationPublicKey []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	previousTransformationKeyIDBuf := NewBufWithData(previousTransformationKeyID)
	defer previousTransformationKeyIDBuf.Close()
	previousPythiaSecretBuf := NewBufWithData(previousPythiaSecret)
	defer previousPythiaSecretBuf.Close()
	previousPythiaScopeSecretBuf := NewBufWithData(previousPythiaScopeSecret)
	defer previousPythiaScopeSecretBuf.Close()
	newTransformationKeyIDBuf := NewBufWithData(newTransformationKeyID)
	defer newTransformationKeyIDBuf.Close()
	newPythiaSecretBuf := NewBufWithData(newPythiaSecret)
	defer newPythiaSecretBuf.Close()
	newPythiaScopeSecretBuf := NewBufWithData(newPythiaScopeSecret)
	defer newPythiaScopeSecretBuf.Close()

	passwordUpdateTokenBuf := NewBuf(BN_SIZE)
	defer passwordUpdateTokenBuf.Close()

	updatedTransformationPublicKeyBuf := NewBuf(G1_SIZE)
	defer updatedTransformationPublicKeyBuf.Close()

	pErr := C.virgil_pythia_get_password_update_token(previousTransformationKeyIDBuf.inBuf, previousPythiaSecretBuf.inBuf, previousPythiaScopeSecretBuf.inBuf,
		newTransformationKeyIDBuf.inBuf, newPythiaSecretBuf.inBuf, newPythiaScopeSecretBuf.inBuf,
		passwordUpdateTokenBuf.inBuf, updatedTransformationPublicKeyBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	return passwordUpdateTokenBuf.GetData(), updatedTransformationPublicKeyBuf.GetData(), nil
}

// UpdateDeblindedWithToken updates previously stored deblinded protected password with token. After this call, Transform() called with new arguments will return corresponding values
func (p *Pythia) UpdateDeblindedWithToken(deblindedPassword, passwordUpdateToken []byte) (updatedDeblindedPassword []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	deblindedPasswordBuf := NewBufWithData(deblindedPassword)
	defer deblindedPasswordBuf.Close()
	passwordUpdateTokenBuf := NewBufWithData(passwordUpdateToken)
	defer passwordUpdateTokenBuf.Close()

	updatedDeblindedPasswordBuf := NewBuf(GT_SIZE)
	defer updatedDeblindedPasswordBuf.Close()
	pErr := C.virgil_pythia_update_deblinded_with_token(deblindedPasswordBuf.inBuf, passwordUpdateTokenBuf.inBuf, updatedDeblindedPasswordBuf.inBuf)
	if pErr != 0 {
		err = errors.New("Internal Pythia error")
		return
	}

	return updatedDeblindedPasswordBuf.GetData(), nil
}
