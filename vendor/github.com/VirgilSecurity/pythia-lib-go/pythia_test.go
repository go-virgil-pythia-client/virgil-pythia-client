package pythia

import (
	"testing"

	"encoding/hex"

	"crypto/subtle"

	"github.com/stretchr/testify/assert"
)

const (
	password   = "password"
	domain1    = "virgil.com"
	username   = "alice"
	msk1       = "master secret"
	sss1       = "server secret"
	domain2    = "virgilsecurity.com"
	msk2       = "super master secret"
	sss2       = "new server secret"
	deblinded1 = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c"
	deblinded2 = "05a00496503c4b36c9fc447c2553387ff3c53417d5c1d2c4183e8cc84ef6fc2aade5e6cf4d4e1eda76a024803a9af3c90ffd4b991c959e101f5a18c6c373768942ad1f987d2ca80773e430e2039324943a16dfc3a90e03550a3b6dc50aa7f6160b91ade09aa99c712b9d6b6982884247e3eb3bdea58e9cf1201b587dfc6df3721a8d74a5c29e06b57c952dc26164300a0defa4fa483fda11514acfcf6ca13c73eaf67f7a8215e7a6284e1f575cf05dbf55e08801380519956a15e4c3b97e8e6c04eadee78c9d02318b7321e87c3d393e4e79ebed32d89960c1e4c2648b7216bd2d01d67330697804d30fa3c2beaca060165c27020b17c3d6273f7f5146eb24d379c97f97e5ee560390c7c7cf19710e056d521a8955ebcfc88dd38af24015c54d060997c10c430c4466613e3447229c3c2d3dbcff3e246ecbe9a7641ff13b68c72b691c211a6dc40bc9684f54e388929916eecfbfb476aaf47961413f2695ec985b25de76a8c5d5caa13520ef600b2df69e8574729026a4b5d80461348fb67d05"
)

var (
	p = New()
)

func TestBlindIsStable(t *testing.T) {
	for i := 0; i < 830; i++ {
		p.Blind([]byte("1234"))
	}
}

func TestBlindEvalDeblind(t *testing.T) {
	t.Parallel()
	vals := make(map[string]bool)

	for i := 0; i < 100; i++ {
		blinded, secret, err := p.Blind([]byte(password))
		assert.NoError(t, err)

		y, _, _, err := p.Transform(blinded, []byte(domain1), []byte(username), []byte(msk1), []byte(sss1))
		assert.NoError(t, err)
		res, err := p.Deblind(y, secret)
		assert.NoError(t, err)
		assert.Equal(t, deblinded1, hex.EncodeToString(res))

		//check if random
		blhex := hex.EncodeToString(blinded)
		sechex := hex.EncodeToString(secret)
		if _, ok := vals[blhex]; ok {
			assert.Fail(t, "blinded values must be random")
		} else {
			vals[blhex] = true
		}

		if _, ok := vals[sechex]; ok {
			assert.Fail(t, "secret values must be random")
		} else {
			vals[sechex] = true
		}
	}
}

func TestFullProto(t *testing.T) {
	t.Parallel()
	blinded, y, kw, tTilde, _, err := simpleProto(password, domain1, username, msk1, sss1)

	assert.NoError(t, err)
	pub, c, u, _ := p.Prove(y, blinded, tTilde, kw)

	assert.Nil(t, p.Verify(y, blinded, []byte(username), pub, c, u))
}

func TestUpdateWithToken(t *testing.T) {
	t.Parallel()
	blinded, y, kw, tTilde, res, err := simpleProto(password, domain1, username, msk1, sss1)
	assert.NoError(t, err)
	pub, c, u, err := p.Prove(y, blinded, tTilde, kw)
	assert.NoError(t, err)

	assert.Nil(t, p.Verify(y, blinded, []byte(username), pub, c, u))

	token, newP, err := p.GetPasswordUpdateToken([]byte(domain1), []byte(msk1), []byte(sss1), []byte(domain2), []byte(msk2), []byte(sss2))
	assert.NoError(t, err)

	newRes, err := p.UpdateDeblindedWithToken(res, token)
	assert.NoError(t, err)

	blinded1, y1, kw1, tTilde1, res1, err := simpleProto(password, domain2, username, msk2, sss2)
	assert.NoError(t, err)

	assert.Equal(t, 1, subtle.ConstantTimeCompare(newRes, res1))
	assert.Equal(t, deblinded2, hex.EncodeToString(res1))

	p1, _, _, err := p.Prove(y1, blinded1, tTilde1, kw1)
	assert.NoError(t, err)
	assert.Equal(t, newP, p1)
}

func simpleProto(password, domain, userName, masterSecret, serverSecret string) (blinded []byte, evald []byte, kw []byte, tTilde []byte, deblinded []byte, err error) {
	blinded, secret, err := p.Blind([]byte(password))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	y, kw, tTilde, err := p.Transform(blinded, []byte(domain), []byte(userName), []byte(masterSecret), []byte(serverSecret))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	deblinded, err = p.Deblind(y, secret)
	return blinded, y, kw, tTilde, deblinded, err
}

func BenchmarkBlind(b *testing.B) {

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := p.Blind([]byte(password))
			if err != nil {
				panic(err)
			}
		}
	})

}

func BenchmarkEval(b *testing.B) {
	blinded, _, err := p.Blind([]byte(password))
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _, err := p.Transform(blinded, []byte(domain1), []byte(username), []byte(msk1), []byte(sss1))
			if err != nil {
				panic(err)
			}
		}
	})

}

func BenchmarkDeblind(b *testing.B) {

	blinded, secret, err := p.Blind([]byte(password))
	if err != nil {
		panic(err)
	}

	y, _, _, err := p.Transform(blinded, []byte(domain1), []byte(username), []byte(msk1), []byte(sss1))
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := p.Deblind(y, secret)
			if err != nil {
				panic(err)
			}
		}
	})

}

func BenchmarkProve(b *testing.B) {

	blinded, _, err := p.Blind([]byte(password))
	if err != nil {
		panic(err)
	}

	y, kw, tTilde, err := p.Transform(blinded, []byte(domain1), []byte(username), []byte(msk1), []byte(sss1))
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _, err := p.Prove(y, blinded, tTilde, kw)
			assert.NoError(b, err)
		}
	})

}

func BenchmarkVerify(b *testing.B) {

	blinded, _, err := p.Blind([]byte(password))
	if err != nil {
		panic(err)
	}

	y, kw, tTilde, err := p.Transform(blinded, []byte(domain1), []byte(username), []byte(msk1), []byte(sss1))
	if err != nil {
		panic(err)
	}

	pub, c, u, err := p.Prove(y, blinded, tTilde, kw)
	assert.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := 0; i < b.N; i++ {
				assert.Nil(b, p.Verify(y, blinded, []byte(username), pub, c, u))
			}
		}
	})

}

func BenchmarkGetToken(b *testing.B) {

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := p.GetPasswordUpdateToken([]byte(domain1), []byte(msk1), []byte(sss1), []byte(domain2), []byte(msk2), []byte(sss2))
			assert.NoError(b, err)
		}
	})
}

func BenchmarkUpdateWithToken(b *testing.B) {

	token, _, err := p.GetPasswordUpdateToken([]byte(domain1), []byte(msk1), []byte(sss1), []byte(domain2), []byte(msk2), []byte(sss2))
	assert.NoError(b, err)
	res1, _ := hex.DecodeString(deblinded1)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := p.UpdateDeblindedWithToken(res1, token)
			assert.NoError(b, err)
		}
	})
}
