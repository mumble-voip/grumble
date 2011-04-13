package main

import (
	"log"
	"time"
	"net"
	"crypto/tls"
	"crypto/rand"
	"encoding/pem"
	"crypto/x509"
	"io/ioutil"
)

func NewTLSListener(port int) (rl *tls.Listener) {
	rl = nil

	// Load the certificate
	pemBytes, err := ioutil.ReadFile("grumble.crt")
	if err != nil {
		log.Printf("Failed to read server.crt: %s", err)
		return
	}

	// Decode the certificate
	cert, _ := pem.Decode(pemBytes)
	if cert == nil {
		log.Printf("Failed to parse server.crt")
		return
	}

	// Load the private key
	keyBytes, err := ioutil.ReadFile("grumble.key")
	if err != nil {
		log.Printf("Failed to read server.key.insecure: %s", err)
		return
	}

	// Decode the private key
	pkPEM, _ := pem.Decode(keyBytes)
	if pkPEM == nil {
		log.Printf("Failed to parse server.key.insecure: %s", err)
		return
	}

	// Determine if we are an RSA private key
	if pkPEM.Type != "RSA PRIVATE KEY" {
		log.Printf("server.key.insecure is not an RSA private key. Found '%s'",
			pkPEM.Type)
		return
	}

	// Check if the PEM file has headers. This will typically
	// mean that it requires a passphrase to decrypt it. For now,
	// let us just assume that people will decrypt them for us, so
	// we can use them without too much work.
	if len(pkPEM.Headers) != 0 {
		log.Printf("server.key.insecure has headers and is probably encrypted.")
		return
	}

	// Parse the PKCS12 private key.
	priv, err := x509.ParsePKCS1PrivateKey(pkPEM.Bytes)
	if err != nil {
		log.Printf("Invalid key in server.key.insecure: %s", err)
		return
	}

	// Create a new TLS config.
	config := new(tls.Config)
	config.Rand = rand.Reader
	config.Time = time.Seconds
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0].Certificate = [][]byte{cert.Bytes}
	config.Certificates[0].PrivateKey = priv
	config.AuthenticateClient = true

	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		net.ParseIP("0.0.0.0"),
		port,
	})
	if err != nil {
		log.Printf("Cannot bind: %s\n", err)
		return
	}

	rl = tls.NewListener(l, config)

	return
}
