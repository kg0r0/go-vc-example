package main

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/piprate/json-gold/ld"
)

type KeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (k KeyPair) createCredential(claim map[string]interface{}) (interface{}, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	expanded, err := proc.Expand(claim, options)
	if err != nil {
		return nil, err
	}
	for _, v := range expanded {
		proof := map[string]interface{}{
			"type":               "DataIntegrityProof",
			"cryptosuite":        "ed25519",
			"created":            time.Now(),
			"verificationMethod": "https://university.example/issuers/14#key-1",
			"proofPurpose":       "assertionMethod",
			"proofValue":         ed25519.Sign(k.privateKey, []byte(fmt.Sprintf("%v", v))),
		}
		v.(map[string]interface{})["proof"] = proof
	}
	return expanded[0], nil
}

func (k KeyPair) verifyCredential(credential interface{}) bool {
	proof := credential.(map[string]interface{})["proof"].(map[string]interface{})
	delete(credential.(map[string]interface{}), "proof")
	return ed25519.Verify(k.publicKey, []byte(fmt.Sprintf("%v", credential)), proof["proofValue"].([]byte))
}

func (k KeyPair) createPresentation(claim map[string]interface{}, credential interface{}) (interface{}, error) {
	return nil, nil
}

func (k KeyPair) verifyPresentation(presentation interface{}) bool {
	return false
}

func main() {
	issuerPubKey, issuerPrivKey, _ := ed25519.GenerateKey(nil)
	k := KeyPair{
		publicKey:  issuerPubKey,
		privateKey: issuerPrivKey,
	}

	claim := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		"id": "http://university.example/credentials/1872",
		"type": []interface{}{
			"VerifiableCredential",
			"ExampleAlumniCredential",
		},
		"issuer":    "https://university.example/issuers/565049",
		"validFrom": "2010-01-01T19:23:24Z",
		"credentialSubject": map[string]interface{}{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"alumniOf": map[string]interface{}{
				"id":   "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name": "Example University",
			},
		},
	}
	vc, err := k.createCredential(claim)
	if err != nil {
		panic(err)
	}
	ld.PrintDocument("Verifiable Credential: ", vc)
	fmt.Printf("Result: %v\n", k.verifyCredential(vc))
}
