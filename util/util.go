package util

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
)

func GetPublicKeyFromPem(in []byte) interface{} {
	bloc, _ := pem.Decode(in)
	key, err := x509.ParsePKIXPublicKey(bloc.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

func GetCertFromPem(cert []byte, key []byte) *tls.Certificate {
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}

	return &c
}

func GetPrivateKeyFromPem(in []byte) interface{} {
	bloc, _ := pem.Decode(in)
	key, err := x509.ParsePKCS1PrivateKey(bloc.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}
