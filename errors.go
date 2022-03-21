package ckks

import "errors"

// Various errors facing the user.
var (
	ErrBadEncoding             = errors.New("input vector and instance are incompatible")
	ErrInconsistentKey         = errors.New("inconsistent key")
	ErrLevelOverflow           = errors.New("homomorphic level overflow")
	ErrWarningInsecure         = errors.New("warning: insecure parameters")
	ErrIncompatibleCiphertexts = errors.New("incompatible ciphertexts rescale")
)

// ErrBadParameters represent inconsistent parameters when creating an instance.
func ErrBadParameters(errMsg string) error {
	return errors.New("bad parameters: " + errMsg)
}
