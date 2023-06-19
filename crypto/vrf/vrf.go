package vrf

import (
	"fmt"
	"math/big"
)

// defaultVrf is assigned to vrfEd25519r2ishiguro by init() of vrf_r2ishguro.go
// If you want to use libsodium for vrf implementation, then you should put build option like this
// `make build LIBSODIUM=1`
// Please refer https://github.com/Finschia/ostracon/pull/41 for more detail
//
// DefaultVrf is now libsodium's and OldVrf is r2ishiguro's.
var DefaultVrf vrfEd25519
var OldVrf vrfEd25519

type Proof []byte
type Output []byte

type vrfEd25519 interface {
	Prove(privateKey []byte, message []byte) (Proof, error)
	Verify(publicKey []byte, proof Proof, message []byte) (bool, error)
	ProofToHash(proof Proof) (Output, error)

	ProofSize() int
	OutputSize() int
}

func (op Output) ToInt() *big.Int {
	i := big.Int{}
	i.SetBytes(op)
	return &i
}

func Prove(privateKey []byte, message []byte) (Proof, error) {
	return DefaultVrf.Prove(privateKey, message)
}

func Verify(publicKey []byte, proof Proof, message []byte) (bool, error) {
	switch proofSize := len(proof); proofSize {
	case DefaultVrf.ProofSize():
		return DefaultVrf.Verify(publicKey, proof, message)
	case OldVrf.ProofSize():
		return OldVrf.Verify(publicKey, proof, message)
	default:
		return false, fmt.Errorf("Invalid vrf proof size: %d", proofSize)
	}
}

func ProofToHash(proof Proof) (Output, error) {
	switch proofSize := len(proof); proofSize {
	case DefaultVrf.ProofSize():
		return DefaultVrf.ProofToHash(proof)
	case OldVrf.ProofSize():
		return OldVrf.ProofToHash(proof)
	default:
		return nil, fmt.Errorf("Invalid vrf proof size: %d", proofSize)
	}
}
