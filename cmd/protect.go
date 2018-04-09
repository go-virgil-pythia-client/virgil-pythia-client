package cmd

import (
	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil-pythia-client.v0/client"
	"github.com/VirgilSecurity/pythia-lib-go"
	"fmt"
	"encoding/hex"
)

type EvalRequest struct {
	W []byte `json:"w"`
	T []byte `json:"t"`
	X []byte `json:"x"`
}

type ProofResponse struct {
	P []byte `json:"p"`
	C []byte `json:"c"`
	U []byte `json:"u"`
}

type EvalResponse struct {
	Y     []byte         `json:"y"`
	Proof *ProofResponse `json:"proof,omitempty"`
}


func Protect(client *common.VirgilHttpClient, pythia *pythia.Pythia) *cli.Command {
	return &cli.Command{
		Name:      "protect",
		Aliases:   []string{"p"},
		Usage:     "protect username password > protected-password",
		Action: func(context *cli.Context) error {
			return protectFunc(context, client, pythia)
		},
	}
}


func protectFunc (c *cli.Context, client *common.VirgilHttpClient, pythia *pythia.Pythia) error {
	if c.Args().Len() != 2 {
		return cli.Exit("invalid number of arguments", 1)
	}

	pass := []byte(c.Args().Get(1))

	blinded, secret, err := pythia.Blind(pass)

	if err != nil{
		return cli.Exit(err, 1)
	}

	req := &EvalRequest{
		T: []byte(c.Args().First()),
		X: blinded,
		W: []byte(c.String("clientId")),
	}

	var resp *EvalResponse

	_, err = client.Send("POST","/api/v1/eval", req, &resp)

	if err != nil{
		return cli.Exit(err, 1)
	}

	deblinded, err := pythia.Deblind(resp.Y, secret)

	fmt.Print(hex.EncodeToString(deblinded))

	return nil
}
