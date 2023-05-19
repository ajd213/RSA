package alexrsa

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// A place to store the public key
type PublicKey struct {
	N *big.Int
	E *big.Int
}

// A place to store the corresponding private key
type PrivateKey struct {
	N *big.Int
	D *big.Int
}

// Generate a public/private key pair for RSA
func GenerateKeys(bitlen int) (*PublicKey, *PrivateKey, error) {
	numRetries := 0

	// an infinite loop
	for {

		numRetries++
		if numRetries == 10 {
			panic("Retried too many times, something's wrong!")
		}

		// Generate p and q with bitlen/2 bits each. We require that
		// the top bits are set, which should be the case using rand.Prime

		// rand.Reader is a global shared instance of an RNG suitable for crypto
		p, err := rand.Prime(rand.Reader, bitlen/2)
		if err != nil {
			return nil, nil, err
		}

		q, err := rand.Prime(rand.Reader, bitlen/2)
		if err != nil {
			return nil, nil, err
		}

		// compute n = pq
		// new() returns a pointer to zero-d memory
		n := new(big.Int).Set(p)
		n.Mul(n, q)

		if n.BitLen() != bitlen {
			// n is the wrong length. Try again!
			continue
		}

		// Compute the totient phi(n) = (p-1)(q-1)
		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))
		phin := new(big.Int).Set(p)
		phin.Mul(phin, q)

		// This value of e is basically always used!
		e := big.NewInt(65537)

		// compute d such that de = 1 (mod phi(n)). d is the
		// multiplicative inverse of e modulo phi(n).
		d := new(big.Int).ModInverse(e, phin)
		if d == nil {
			// e and phi(n) are not relatively prime!
			// this could occur if p-1 or q-1 has e
			// as a factor. Retry!
			continue
		}

		pub := &PublicKey{N: n, E: e}
		priv := &PrivateKey{N: n, D: d}

		return pub, priv, nil

	}
}

// Encrypt a message m using the public key.
func encrypt(pub *PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	// c = m^e (mod n)
	c.Exp(m, pub.E, pub.N)
	return c
}

// Decrypt a cipher c using the private key.
func decrypt(priv *PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	// m = c^d (mod n)
	m.Exp(c, priv.D, priv.N)
	return m
}

func EncryptRSA(pub *PublicKey, m []byte) ([]byte, error) {

	// Compute the length of the key in Bytes.
	// Round up
	keyLen := (pub.N.BitLen() + 7) / 8
	if len(m) > keyLen-11 {
		return nil, fmt.Errorf("len(m)=%v too long!", len(m))
	}

	// Now we create a block for encryption, which has the same
	// length as the key

	paddingLen := keyLen - len(m) - 3

	// The encrypted byte
	eb := make([]byte, keyLen)

	// Mark the start of the padding
	eb[0] = 0x00
	eb[1] = 0x02

	// Fill in the rest of the padding with NONZERO bytes
	for i := 2; i < 2+paddingLen; {

		// Place a random byte at eb[i]
		_, err := rand.Read(eb[i : i+1])
		// Check for errors
		if err != nil {
			return nil, err
		}
		// If the byte is zero, do not advance i
		if eb[i] != 0x00 {
			i++
		}
	}
	// Terminate the padding with a zero.
	// After decryption, this allows us to strip the padding.
	eb[2+paddingLen] = 0x00

	// Copy the message m into the rest of the encryption block
	copy(eb[3+paddingLen:], m)

	// Now we have made the encryption block, we take it as an m-byte
	// big.Int and RSA encrypt it with the public key
	mnum := new(big.Int).SetBytes(eb)
	c := encrypt(pub, mnum)

	// c (the cypher text) is a big.Int. We need it to be a byte slice of length
	// keyLen. Usually this is not needed.

	cypherPadLen := keyLen - len(c.Bytes())
	for i := 0; i < cypherPadLen; i++ {
		eb[i] = 0x00
	}
	copy(eb[cypherPadLen:], c.Bytes())
	return eb, nil
}

func DecryptRSA(priv *PrivateKey, c []byte) ([]byte, error) {
	keyLen := (priv.N.BitLen() + 7) / 8
	if len(c) != keyLen {
		return nil, fmt.Errorf("len(c) = %v. Expected len(c) = Keylen = %v", len(c), keyLen)
	}

	// Convert c into a big.Int and decrypt it using the private key
	cnum := new(big.Int).SetBytes(c)
	mnum := decrypt(priv, cnum)

	// Write the bytes of mnum into m, left-padding if needed
	m := make([]byte, keyLen)
	copy(m[keyLen-len(mnum.Bytes()):], mnum.Bytes())

	// check for the 0x00 0x02 signature
	if m[0] != 0x00 || m[1] != 0x02 {
		return nil, fmt.Errorf("m[0]=%v, m[1]=%v. Expected 0x00, 0x02", m[0], m[1])
	}

	// Skip over the random padding. IndexByte searches for the first instance of
	// 0x00. +2 to account for the 0x00 0x02 signature
	endPad := bytes.IndexByte(m[2:], 0x00) + 2
	if endPad < 2 {
		return nil, fmt.Errorf("End of padding not found!")
	}

	return m[endPad+1:], nil
}
