package main

import (
	"github.com/VirgilSecurity/pythia-lib-go"
	"fmt"
	"encoding/hex"
)

func main() {

	p := pythia.New()

	blinded, secret, err := p.Blind([]byte("abc"))
	if err != nil{
		panic(err)
	}

	fmt.Println(hex.EncodeToString(blinded))
	fmt.Println(hex.EncodeToString(secret))
	
}
