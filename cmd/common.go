package cmd

import (
	"github.com/VirgilSecurity/pythia-lib-go"
	"gopkg.in/urfave/cli.v2"
	"fmt"
	"os"
	"encoding/hex"
	"gopkg.in/virgil-pythia-client.v0/client"
	"github.com/pkg/errors"
)

func RequestEval (c *cli.Context, client *common.VirgilHttpClient, pythia *pythia.Pythia) ([]byte, error) {
	if c.Args().Len() != 2 {
		return nil, errors.New("invalid number of arguments")
	}

	pass := []byte(c.Args().Get(1))

	blinded, secret, err := pythia.Blind(pass)
	fmt.Fprintf(os.Stderr, "blinded password: %s\n", hex.EncodeToString(blinded))

	if err != nil{
		return nil, err
	}

	req := &EvalRequest{
		T: []byte(c.Args().First()),
		X: blinded,
		W: []byte(c.String("clientId")),
	}

	var resp *EvalResponse

	_, err = client.Send("POST","/api/v1/eval", req, &resp)

	if err != nil{
		return nil, err
	}

	deblinded, err := pythia.Deblind(resp.Y, secret)

	return deblinded, err
}
