package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type KeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type IssuerMetadata struct {
	context   []string
	id        string
	types     []string
	issuer    string
	validFrom time.Time
}

type Claim struct {
	id     string
	degree Degree
}

type Degree struct {
	types string
	name  string
}

type Proof struct {
	types              string
	cryptosuite        string
	created            time.Time
	verificationMethod string
	proofPurpose       string
	proofValue         []byte
}

type Credential struct {
	context           []string
	id                string
	types             []string
	issuer            string
	validFrom         time.Time
	credentialSubject Claim
	proof             Proof
}

func createCredential(keyPair KeyPair, metadata IssuerMetadata, claim Claim) Credential {
	credential := Credential{
		context:           metadata.context,
		id:                metadata.id,
		types:             metadata.types,
		issuer:            metadata.issuer,
		validFrom:         metadata.validFrom,
		credentialSubject: claim,
	}
	proof := Proof{
		types:              "DataIntegrityProof",
		cryptosuite:        "ed25519",
		created:            time.Now(),
		verificationMethod: "https://university.example/issuers/14#key-1",
		proofPurpose:       "assertionMethod",
		proofValue:         ed25519.Sign(keyPair.privateKey, []byte(fmt.Sprintf("%v", credential))),
	}
	credential.proof = proof
	return credential
}

func verifyCredential(publicKey ed25519.PublicKey, credential Credential) bool {
	proof := credential.proof
	credential.proof = Proof{}
	return ed25519.Verify(publicKey, []byte(fmt.Sprintf("%v", credential)), proof.proofValue)
}
