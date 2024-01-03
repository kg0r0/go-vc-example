package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

func main() {
	issuerPubKey, issuerPrivKey, _ := ed25519.GenerateKey(nil)
	keyPair := KeyPair{
		publicKey:  issuerPubKey,
		privateKey: issuerPrivKey,
	}

	metadata := IssuerMetadata{
		context:   []string{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		id:        "http://university.example/credentials/1872",
		types:     []string{"VerifiableCredential", "ExampleAlumniCredential"},
		issuer:    "https://university.example/issuers/565049",
		validFrom: time.Now(),
	}

	claim := Claim{
		id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		degree: Degree{
			name:  "Bachelor of Science and Arts",
			types: "ExampleBachelorDegree",
		},
	}
	vc := createCredential(keyPair, metadata, claim)
	fmt.Println(verifyCredential(keyPair.publicKey, vc))

	holderPubKey, holderPrivKey, _ := ed25519.GenerateKey(nil)
	holderKeyPair := KeyPair{
		publicKey:  holderPubKey,
		privateKey: holderPrivKey,
	}

	holderMetadata := HolderMetadata{
		context: []string{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		types:   []string{"VerifiablePresentation", "ExamplePresentation"},
	}
	vp := createPresentation(holderKeyPair, holderMetadata, vc)
	fmt.Println(verifyPresentation(holderKeyPair.publicKey, vp))
}
