# virgil-pythia-client
A demo client for VirgilSecurity Pythia Service

# Usage example:

```bash
$ export CLIENT_ID=`openssl rand -base64 48`
$ go get -u gopkg.in/virgil-pythia-client.v0
$ go/bin/virgil-pythia-client.v0 p Alice p@$$w0Rd > protected-password
$ go/bin/virgil-pythia-client.v0 c Alice p@$$w0Rd < protected-password
password match
$ go/bin/virgil-pythia-client.v0 c Alice p@$$w0Rd1 < protected-password
password does not match
$ go/bin/virgil-pythia-client.v0 c Alice p@$$w0Rd < protected-password
password match
```
