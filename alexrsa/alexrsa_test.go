package alexrsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	pub, priv, err := GenerateKeys(2048)

	if err != nil {
		t.Fatal(err)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("pub.N.BitLen() should be 2048. Got %v", pub.N.BitLen())
	}
	if priv.N.BitLen() != 2048 {
		t.Errorf("priv.N.BitLen() should be 2048. Got %v", priv.N.BitLen())
	}
	if priv.N != pub.N {
		t.Errorf("priv.N = %v. pub.N = %v. Should be equal!", priv.N, pub.N)
	}
}

func TestEncryptDecryptReversible(t *testing.T) {
	pub, priv, err := GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("This is Alex's module!")
	c, err := EncryptRSA(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecryptRSA(priv, c)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(p, msg) != 0 {
		t.Errorf("Require p = msg. Got p = %v, msg = %v", p, msg)

	}
}

// Encrypt with our encryption, decrypt with rsa.DecryptPKCS1v15
func TestEncryptThenDecryptWithStdlib(t *testing.T) {
	pub, priv, err := GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("The quick brown fox jumps over the lazy dog")
	c, err := EncryptRSA(pub, msg)

	var rsapriv rsa.PrivateKey
	rsapriv.N = pub.N
	rsapriv.E = int(pub.E.Int64())
	rsapriv.D = priv.D

	p, err := rsa.DecryptPKCS1v15(nil, &rsapriv, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(p, msg) != 0 {
		t.Errorf("want p == msg, got p = %v, msg = %v", p, msg)
	}
}

// Encrypt with rsa.EncryptPKCS1v15, decrypt with our decryption
func TestEncryptWithStdlibThenDecrypt(t *testing.T) {
	pub, priv, err := GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	var rsapub rsa.PublicKey
	rsapub.N = pub.N
	rsapub.E = int(pub.E.Int64())

	msg := []byte("This is going to be a piece of cake")
	c, err := rsa.EncryptPKCS1v15(rand.Reader, &rsapub, msg)
	if err != nil {
		t.Fatal(err)
	}

	p, err := DecryptRSA(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(p, msg) != 0 {
		t.Errorf("want p == msg, got p = %v, msg = %v", p, msg)
	}
}
