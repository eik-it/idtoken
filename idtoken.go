// Package idtoken verifies magic-auth ID tokens. It is the one supported way
// for an App to accept a sign-in: a single call, Verifier.Verify, checks the
// signature against the App's JWKS, the issuer, the audience, the expiry and
// the nonce, and then spends the token's jti through a used-token store the
// App supplies, so a token is accepted at most once.
//
// It is its own Go module and uses only the standard library, so an App can
// depend on it without depending on magic-auth's server or its framework.
//
// # The token
//
// An ID token is a compact JWS signed with EdDSA (Ed25519) under the App's own
// Signing key, with the key's kid in the header. Its claims are iss (the
// App's issuer, https://auth.heldig.org/c/{app}), aud (the App identifier),
// sub (the User's stable identifier, a UUID independent of the address),
// email, email_verified (always true), nonce, jti, iat and exp. exp is at
// most two minutes after iat.
//
// magic-auth returns the token in the query string of the App's redirect URI
// (a deliberate deviation from OpenID Connect), so a generic OIDC
// client library rejects the response; use this package. The callback should
// verify, create its own session and redirect at once to a URL without the
// token, sending Referrer-Policy: no-referrer.
//
// # Usage
//
//	v, err := idtoken.NewVerifier(idtoken.Config{
//		Issuer:     "https://auth.heldig.org/c/export-fish",
//		Audience:   "export-fish",
//		UsedTokens: myStore, // e.g. a table with a unique jti column
//	})
//	claims, err := v.Verify(ctx, r.URL.Query().Get("id_token"), nonceFromMySession)
//
// Every failure wraps one of the Err* sentinels below (test with errors.Is),
// except a failure of the caller's own UsedTokens store, which is returned
// wrapped around the store's error and is likewise never an acceptance.
package idtoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

// Algorithm is the only JWS algorithm magic-auth signs with.
const Algorithm = "EdDSA"

// MaxLifetime is the longest an ID token lives. Verify refuses a token whose
// exp is further than this from its iat.
const MaxLifetime = 2 * time.Minute

// Claims is an ID token's payload.
type Claims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce"`
	ID            string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	Expiry        int64  `json:"exp"`
}

// IssuedAtTime is iat as a time.
func (c Claims) IssuedAtTime() time.Time { return time.Unix(c.IssuedAt, 0).UTC() }

// ExpiresAt is exp as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0).UTC() }

// The verification failures. Verify wraps exactly one of them, unless the
// caller's UsedTokens store failed.
var (
	ErrMalformed  = errors.New("idtoken: malformed token")
	ErrAlgorithm  = errors.New("idtoken: unsupported algorithm")
	ErrUnknownKey = errors.New("idtoken: unknown key ID")
	ErrSignature  = errors.New("idtoken: invalid signature")
	ErrIssuer     = errors.New("idtoken: wrong issuer")
	ErrAudience   = errors.New("idtoken: wrong audience")
	ErrExpired    = errors.New("idtoken: token expired")
	ErrNotYet     = errors.New("idtoken: token issued in the future")
	ErrLifetime   = errors.New("idtoken: token lifetime exceeds two minutes")
	ErrNonce      = errors.New("idtoken: wrong nonce")
	ErrReused     = errors.New("idtoken: token already used")
	// ErrKeySet: the issuer's JWKS could not be fetched (and no unexpired
	// or stale-but-allowed key answers for the kid). Not a verdict on the
	// token: retry later.
	ErrKeySet = errors.New("idtoken: the issuer's key set is unavailable")
)

// JWK is one public key in a JWKS: an OKP Ed25519 key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// JWKS is a JSON Web Key Set, as served at {issuer}/.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK is pub as a signing JWK named kid.
func PublicJWK(pub ed25519.PublicKey, kid string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: kid, Use: "sig", Alg: Algorithm}
}

// PublicKey decodes the JWK's key, refusing anything but an Ed25519 OKP key.
func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Alg != "" && k.Alg != Algorithm) || (k.Use != "" && k.Use != "sig") {
		return nil, ErrAlgorithm
	}
	b, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrMalformed
	}
	return ed25519.PublicKey(b), nil
}

// Sign issues an ID token: claims signed with priv, kid in the header. It is
// magic-auth's issuing half, exported so an App's own tests can mint tokens
// against a test key and StaticKeys.
func Sign(priv ed25519.PrivateKey, kid string, c Claims) (string, error) {
	return signJWS(priv, header{Alg: Algorithm, Kid: kid, Typ: "JWT"}, c)
}
