package main

import (
	"crypto/tls"
	"encoding/pem"
	"log"
	"net"
	"os"
	"os/exec"
)

// addTrustedRoot adds the DER-encoded certificate to the system's trust store.
func addTrustedRoot(rootCert []byte) {
	certOut, err := os.Create("/tmp/mitm_root.crt")
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert})
	certOut.Close()

	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", "/tmp/mitm_root.crt")
	if err = cmd.Run(); err != nil {
		log.Fatalf("failed to add to trust store: %v", err)
	}
}

// rmTrustedRoot removes the certificate from the system's trust store and keychain.
func rmTrustedRoot() {
	cmd := exec.Command("security", "remove-trusted-cert", "-d", "/tmp/mitm_root.crt")
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to remove from trust store: %v", err)
	}

	cmd = exec.Command("security", "delete-certificate", "-c", "Generic Inc.", "/Library/Keychains/System.keychain")
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to remove from keychain: %v", err)
	}
}

// newServer returns a new TLS listener with a system-trusted certificate. It returns the PEM of the root certificate.
func newServer() (net.Listener, []byte, error) {
	rootCert, rootPriv, err := generateRootCert()
	if err != nil {
		return nil, nil, err
	}

	leafCert, leafPriv, err := generateLeafCert(rootCert, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tls.Certificate{
			Certificate: [][]byte{leafCert, rootCert},
			PrivateKey:  leafPriv,
		}},
	}
	l, err := tls.Listen("tcp", *laddr, config)
	return l, rootCert, err
}
