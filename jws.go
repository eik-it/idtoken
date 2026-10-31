package idtoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// header is the JWS protected header. Only these members are written or read.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// maxTokenLength bounds what parseJWS accepts, so an oversized input cannot
// make the verifier allocate on a caller's behalf.
const maxTokenLength = 8 << 10

var b64 = base64.RawURLEncoding

func signJWS(priv ed25519.PrivateKey, h header, claims any) (string, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	return input + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(input))), nil
}

// jws is a structurally valid compact JWS whose signature is NOT yet checked.
type jws struct {
	header       header
	payload      []byte
	signingInput []byte
	signature    []byte
}

func parseJWS(token string) (jws, error) {
	if len(token) > maxTokenLength {
		return jws{}, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jws{}, ErrMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return jws{}, ErrMalformed
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return jws{}, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return jws{}, ErrMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return jws{}, ErrMalformed
	}
	return jws{header: h, payload: payload, signingInput: []byte(parts[0] + "." + parts[1]), signature: sig}, nil
}

func (t jws) verify(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && len(t.signature) == ed25519.SignatureSize &&
		ed25519.Verify(pub, t.signingInput, t.signature)
}
