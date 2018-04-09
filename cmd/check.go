package cmd

import (
	"github.com/VirgilSecurity/pythia-lib-go"
	"gopkg.in/virgil-pythia-client.v0/client"
	"gopkg.in/urfave/cli.v2"
	"os"
	"io/ioutil"
	"encoding/hex"
	"crypto/subtle"
)

func Check(client *common.VirgilHttpClient, pythia *pythia.Pythia) *cli.Command {
	return &cli.Command{
		Name:      "check",
		Aliases:   []string{"c"},
		Usage:     "check username password < protected-password",
		Action: func(context *cli.Context) error {
			return checkFunc(context, client, pythia)
		},
	}
}


func checkFunc (c *cli.Context, client *common.VirgilHttpClient, pythia *pythia.Pythia) error {
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

	read, err := ioutil.ReadAll(os.Stdin)
	if err != nil{
		return cli.Exit(err, 1)
	}

	deblindedHex := hex.EncodeToString(deblinded)

	if subtle.ConstantTimeCompare(read, []byte(deblindedHex)) != 1{
		return cli.Exit("Password does not match", 1)
	} else{
		return cli.Exit("Password match", 0)
	}

	return nil
}
