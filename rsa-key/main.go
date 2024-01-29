// main.go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return
	}

	// Message to sign
	message := []byte("Hello, RSA! This is the message to be signed.")

	// Sign the message
	signature, err := sign(privateKey, message)
	if err != nil {
		fmt.Println("Error signing the message:", err)
		return
	}

	// Save private key to file
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}
	defer privateKeyFile.Close()

	err = savePrivateKey(privateKeyFile, privateKey)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	// Save public key to file
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println("Error creating public key file:", err)
		return
	}
	defer publicKeyFile.Close()

	err = savePublicKey(publicKeyFile, &privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	fmt.Println("RSA key pair generated and saved successfully.")

	// Verify the signature
	if verify(&privateKey.PublicKey, message, signature) {
		fmt.Println("Signature verification successful.")
	} else {
		fmt.Println("Signature verification failed.")
	}
}

// sign creates a digital signature for the given message using the private key
func sign(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// verify checks if the given signature is valid for the message and public key
func verify(publicKey *rsa.PublicKey, message, signature []byte) bool {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}

// savePrivateKey saves the private key to a file in PEM format
func savePrivateKey(file *os.File, key *rsa.PrivateKey) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.Encode(file, privateKeyPEM)
}

// savePublicKey saves the public key to a file in PEM format
func savePublicKey(file *os.File, key *rsa.PublicKey) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.Encode(file, publicKeyPEM)
}
