package u2fserver

// #cgo LDFLAGS: -lu2f-server
// #include <stdlib.h>
// #include <u2f-server/u2f-server.h>
import "C"

import "errors"

var (
	// ==== Common errors ==================================

	// ErrMemory Memory allocation error
	ErrMemory = errors.New("Memory error")

	// ErrJSON Bad JSON format
	ErrJSON = errors.New("Json error")

	// ErrBase64 Bad Base64 format
	ErrBase64 = errors.New("Base64 error")

	// ==== Server errors ==================================

	//ErrCrypto Error in cryptography
	ErrCrypto = errors.New("Cryptographic error")

	// ErrOrigin Origin does not match
	ErrOrigin = errors.New("Origin mismatch")

	// ErrChallenge Challenge error
	ErrChallenge = errors.New("Challenge error")

	// ErrSignature Signature mismatch
	ErrSignature = errors.New("Signature mismatch")

	// ErrFormat Message format error
	ErrFormat = errors.New("Message format error")

	// ==== Errors internal to Go binding ==================================

	// ErrInvalidPubKey Invalid PubKey format
	ErrInvalidPubKey = errors.New("Invalid PubKey format")

	// ErrDeviceNumber Invalid device number
	ErrDeviceNumber = errors.New("Invalid device number")

	//ErrOther Unknown error
	ErrOther = errors.New("Unknown error")
)

var errorList = []error{ErrMemory, ErrJSON, ErrBase64, ErrCrypto, ErrOrigin, ErrChallenge, ErrSignature, ErrFormat}

func iToErr(e C.u2fs_rc) error {
	if e >= 0 {
		return nil
	}

	if e < -8 {
		return ErrOther
	}

	return errorList[-(e - 1)]
}
