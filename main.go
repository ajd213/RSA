package main

import (
	"fmt"
	"log"

	"github.com/ajd213/RSA/alexrsa"
)

func main() {
	keysize := 2048
	pub, priv, err := alexrsa.GenerateKeys(keysize)
	if err != nil {
		panic("Error!")
	}

	msg := "My name is Alex and I'm a sausage."

	fmt.Println(msg)

	cypher, err := alexrsa.EncryptRSA(pub, []byte(msg))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(cypher))

	p, err := alexrsa.DecryptRSA(priv, cypher)

	fmt.Println(string(p))

}
