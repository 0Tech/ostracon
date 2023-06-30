package vrf

import (
	r2ishiguro "github.com/r2ishiguro/vrf/go/vrf_ed25519"
)

const (
	ProofSize = 81
)

var (
	sealed = false
)

func Seal() {
	sealed = true
}

func Verify(publicKey []byte, proof []byte, message []byte) (bool, []byte) {
	if sealed {
		return false, nil
	}

	isValid, err := r2ishiguro.ECVRF_verify(publicKey, proof, message)
	if err != nil || !isValid {
		return false, nil
	}

	hash, err := ProofToHash(proof)
	if err != nil {
		return false, nil
	}

	return true, hash
}

func ProofToHash(proof []byte) ([]byte, error) {
	// validate proof with ECVRF_decode_proof
	_, _, _, err := r2ishiguro.ECVRF_decode_proof(proof)
	if err != nil {
		return nil, err
	}
	return r2ishiguro.ECVRF_proof2hash(proof), nil
}
