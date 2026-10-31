package idtoken

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// UsedTokenStore remembers token IDs (jti) that have been accepted. It is the
// App's own storage -- a table with a unique jti column, a cache with
// set-if-absent -- so single use holds across the App's instances.
type UsedTokenStore interface {
	// MarkUsed atomically records jti as used and reports whether this was
	// its first use. It must remember jti at least until expiresAt; after
	// that the token is refused as expired anyway.
	MarkUsed(ctx context.Context, jti string, expiresAt time.Time) (first bool, err error)
}

// Config configures a Verifier for one App.
type Config struct {
	// Issuer is the App's issuer, https://auth.heldig.org/c/{app}. Required.
	Issuer string
	// Audience is the App identifier (client_id). Required.
	Audience string
	// UsedTokens enforces single use. Required.
	UsedTokens UsedTokenStore
	// Keys resolves kids. Default: a RemoteKeySet over JWKSURL.
	Keys KeySet
	// JWKSURL is where the default key set fetches from. Default:
	// Issuer + "/.well-known/jwks.json".
	JWKSURL string
	// HTTPClient fetches the JWKS. Default: a client with a
	// DefaultFetchTimeout timeout. Each fetch is bounded by that timeout too.
	HTTPClient *http.Client
	// Now is the clock. Default: time.Now.
	Now func() time.Time
	// Leeway tolerates clock skew on exp and iat. Default: 10 seconds.
	// Negative means none.
	Leeway time.Duration
}

// Verifier verifies ID tokens for one App. It is safe for concurrent use.
type Verifier struct {
	issuer, audience string
	used             UsedTokenStore
	keys             KeySet
	now              func() time.Time
	leeway           time.Duration
}

// NewVerifier checks cfg and builds a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("idtoken: Issuer and Audience are required")
	}
	if cfg.UsedTokens == nil {
		return nil, errors.New("idtoken: UsedTokens is required: single use is not optional")
	}
	v := &Verifier{issuer: cfg.Issuer, audience: cfg.Audience, used: cfg.UsedTokens, keys: cfg.Keys, now: cfg.Now, leeway: cfg.Leeway}
	if v.keys == nil {
		url := cfg.JWKSURL
		if url == "" {
			url = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/jwks.json"
		}
		v.keys = NewRemoteKeySet(url, cfg.HTTPClient)
	}
	if v.now == nil {
		v.now = time.Now
	}
	switch {
	case v.leeway == 0:
		v.leeway = 10 * time.Second
	case v.leeway < 0:
		v.leeway = 0
	}
	return v, nil
}

// Verify checks token and returns its claims. nonce is the value the App put
// in the authorize request for this browser. The checks run in this order --
// structure, algorithm, key, signature, issuer, audience, time, nonce -- and
// the token is spent (UsedTokens.MarkUsed) only after all of them pass, so a
// forged or misdirected token can never use up a real one's jti.
func (v *Verifier) Verify(ctx context.Context, token, nonce string) (Claims, error) {
	t, err := parseJWS(token)
	if err != nil {
		return Claims{}, err
	}
	if t.header.Alg != Algorithm {
		return Claims{}, fmt.Errorf("%w %q", ErrAlgorithm, t.header.Alg)
	}
	if t.header.Kid == "" {
		return Claims{}, fmt.Errorf("%w: no kid", ErrUnknownKey)
	}
	pub, err := v.keys.PublicKey(ctx, t.header.Kid)
	if err != nil {
		return Claims{}, err
	}
	if !t.verify(pub) {
		return Claims{}, ErrSignature
	}

	var c Claims
	dec := json.NewDecoder(bytes.NewReader(t.payload))
	if err := dec.Decode(&c); err != nil {
		// An aud array, or any claim of the wrong type, lands here: magic-auth
		// issues exactly one audience, as a string.
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if c.Issuer != v.issuer {
		return Claims{}, fmt.Errorf("%w %q", ErrIssuer, c.Issuer)
	}
	if c.Audience != v.audience {
		return Claims{}, fmt.Errorf("%w %q", ErrAudience, c.Audience)
	}
	if c.Subject == "" || c.ID == "" || c.Email == "" || !c.EmailVerified || c.IssuedAt == 0 || c.Expiry == 0 {
		return Claims{}, fmt.Errorf("%w: a required claim is missing", ErrMalformed)
	}
	now := v.now()
	if !now.Before(c.ExpiresAt().Add(v.leeway)) {
		return Claims{}, ErrExpired
	}
	if c.IssuedAtTime().After(now.Add(v.leeway)) {
		return Claims{}, ErrNotYet
	}
	if c.ExpiresAt().Sub(c.IssuedAtTime()) > MaxLifetime {
		return Claims{}, ErrLifetime
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return Claims{}, ErrNonce
	}
	first, err := v.used.MarkUsed(ctx, c.ID, c.ExpiresAt().Add(v.leeway))
	if err != nil {
		return Claims{}, fmt.Errorf("idtoken: recording the token as used: %w", err)
	}
	if !first {
		return Claims{}, ErrReused
	}
	return c, nil
}
