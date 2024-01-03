package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type HolderMetadata struct {
	context []string
	types   []string
}

type Presentation struct {
	context    []string
	types      []string
	credential Credential
	proof      Proof
}

func createPresentation(keyPair KeyPair, metadata HolderMetadata, credential Credential) Presentation {
	presentation := Presentation{
		context:    metadata.context,
		types:      metadata.types,
		credential: credential,
	}
	proofOfPresentaton := Proof{
		types:              "DataIntegrityProof",
		cryptosuite:        "ed25519",
		created:            time.Now(),
		verificationMethod: "https://university.example/issuers/14#key-1",
		proofPurpose:       "assertionMethod",
		proofValue:         ed25519.Sign(keyPair.privateKey, []byte(fmt.Sprintf("%v", presentation))),
	}
	presentation.proof = proofOfPresentaton
	return presentation
}

func verifyPresentation(publicKey ed25519.PublicKey, presentation Presentation) bool {
	proof := presentation.proof
	presentation.proof = Proof{}
	return ed25519.Verify(publicKey, []byte(fmt.Sprintf("%v", presentation)), proof.proofValue)
}
