package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// generateRootCert returns a self-signed certificate and corresponding private key.
func generateRootCert() ([]byte, *ecdsa.PrivateKey, error) {
	template, priv, err := generateTemplate()
	if err != nil {
		return nil, nil, err
	}
	template.IsCA = true

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root certificate: %s", err)
	}

	return derBytes, priv, err
}

// generateLeafCert takes a serialized root certificate and corresponding private key as input. It returns a certificate
// signed by the root and the corresponding private key.
func generateLeafCert(rootDer []byte, rootKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	rootCert, err := x509.ParseCertificate(rootDer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root: %s", err)
	}

	template, priv, err := generateTemplate()
	if err != nil {
		return nil, nil, err
	}

	template.DNSNames = []string{*sni}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %s", err)
	}

	return derBytes, priv, err
}

// generateTemplate returns a mostly-populated certificate and randomly generated private key.
func generateTemplate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Generic Inc."},
			CommonName:   "Generic Inc.",
		},
		NotBefore: time.Now().Add(-30 * time.Second),
		NotAfter:  time.Now().Add(1 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, priv, nil
}
