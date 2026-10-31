package idtoken_test

// Contract tests for the verification package's public API: every check Verify
// promises has a case that fails it, and nothing else about the token is wrong
// in that case, so each failure is attributable to exactly one check.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eik-it/idtoken"
)

const (
	issuer   = "https://auth.heldig.org/c/export-fish"
	audience = "export-fish"
	nonce    = "n-0S6_WzA2Mj"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer{priv: priv, pub: pub, kid: kid}
}

func (s signer) jwks() idtoken.JWKS {
	return idtoken.JWKS{Keys: []idtoken.JWK{idtoken.PublicJWK(s.pub, s.kid)}}
}

func validClaims() idtoken.Claims {
	return idtoken.Claims{
		Issuer: issuer, Audience: audience, Subject: "7d0b6a52-6a5a-4a2e-9b55-2f1f0f3c9a10",
		Email: "kari@fjordbris.no", EmailVerified: true, Nonce: nonce, ID: "jti-1",
		IssuedAt: now.Unix(), Expiry: now.Add(2 * time.Minute).Unix(),
	}
}

func (s signer) sign(t *testing.T, c idtoken.Claims) string {
	t.Helper()
	tok, err := idtoken.Sign(s.priv, s.kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func verifier(t *testing.T, keys idtoken.JWKS, iss, aud string, at time.Time) *idtoken.Verifier {
	t.Helper()
	set, err := idtoken.StaticKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	v, err := idtoken.NewVerifier(idtoken.Config{
		Issuer: iss, Audience: aud, Keys: set, UsedTokens: &idtoken.MemoryUsedTokens{Now: func() time.Time { return at }},
		Now: func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAValidTokenVerifies(t *testing.T) {
	s := newSigner(t, "k1")
	claims, err := verifier(t, s.jwks(), issuer, audience, now.Add(time.Minute)).Verify(t.Context(), s.sign(t, validClaims()), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if claims != validClaims() {
		t.Fatalf("claims = %+v, want %+v", claims, validClaims())
	}
}

func TestEachCheckFailsOnItsOwn(t *testing.T) {
	s := newSigner(t, "k1")
	other := newSigner(t, "k1") // same kid, different key
	for _, tc := range []struct {
		name  string
		token func() string
		nonce string
		at    time.Time
		want  error
	}{
		{"wrong signature", func() string { return other.sign(t, validClaims()) }, nonce, now, idtoken.ErrSignature},
		{"wrong issuer", func() string {
			c := validClaims()
			c.Issuer = "https://auth.heldig.org/c/sudokuligaen"
			return s.sign(t, c)
		}, nonce, now, idtoken.ErrIssuer},
		{"wrong audience", func() string {
			c := validClaims()
			c.Audience = "sudokuligaen"
			return s.sign(t, c)
		}, nonce, now, idtoken.ErrAudience},
		{"another environment of the same App as audience", func() string {
			c := validClaims()
			c.Audience = "export-fish-test"
			return s.sign(t, c)
		}, nonce, now, idtoken.ErrAudience},
		{"expired", func() string { return s.sign(t, validClaims()) }, nonce, now.Add(3 * time.Minute), idtoken.ErrExpired},
		{"issued in the future", func() string { return s.sign(t, validClaims()) }, nonce, now.Add(-time.Minute), idtoken.ErrNotYet},
		{"lifetime over two minutes", func() string {
			c := validClaims()
			c.Expiry = now.Add(time.Hour).Unix()
			return s.sign(t, c)
		}, nonce, now, idtoken.ErrLifetime},
		{"wrong nonce", func() string { return s.sign(t, validClaims()) }, "another-nonce", now, idtoken.ErrNonce},
		{"no expected nonce", func() string { return s.sign(t, validClaims()) }, "", now, idtoken.ErrNonce},
		{"unknown key ID", func() string { return newSigner(t, "k2").sign(t, validClaims()) }, nonce, now, idtoken.ErrUnknownKey},
		{"alg none", func() string { return unsigned(t, `{"alg":"none","kid":"k1"}`, validClaims()) }, nonce, now, idtoken.ErrAlgorithm},
		{"alg HS256", func() string { return unsigned(t, `{"alg":"HS256","kid":"k1"}`, validClaims()) }, nonce, now, idtoken.ErrAlgorithm},
		{"not a JWS", func() string { return "not.a.token.at.all" }, nonce, now, idtoken.ErrMalformed},
		{"missing sub", func() string {
			c := validClaims()
			c.Subject = ""
			return s.sign(t, c)
		}, nonce, now, idtoken.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier(t, s.jwks(), issuer, audience, tc.at).Verify(t.Context(), tc.token(), tc.nonce)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// unsigned builds a token with an arbitrary header and a junk signature.
func unsigned(t *testing.T, header string, c idtoken.Claims) string {
	t.Helper()
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(body) + "." + enc.EncodeToString(make([]byte, 64))
}

func TestAReusedTokenIsRefused(t *testing.T) {
	s := newSigner(t, "k1")
	v := verifier(t, s.jwks(), issuer, audience, now)
	tok := s.sign(t, validClaims())
	if _, err := v.Verify(t.Context(), tok, nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), tok, nonce); !errors.Is(err, idtoken.ErrReused) {
		t.Fatalf("second use: err = %v, want ErrReused", err)
	}
}

// A token that fails any other check is not spent: a misdirected copy of a
// token (wrong nonce, say) cannot burn the jti its rightful holder needs.
func TestAFailedVerificationDoesNotSpendTheToken(t *testing.T) {
	s := newSigner(t, "k1")
	v := verifier(t, s.jwks(), issuer, audience, now)
	tok := s.sign(t, validClaims())
	if _, err := v.Verify(t.Context(), tok, "wrong"); !errors.Is(err, idtoken.ErrNonce) {
		t.Fatalf("err = %v, want ErrNonce", err)
	}
	if _, err := v.Verify(t.Context(), tok, nonce); err != nil {
		t.Fatalf("the rightful verification failed after a refused one: %v", err)
	}
}

// Each App, and each environment of one App, has its own key and issuer, so
// a token issued to export-fish fails in export-fish-test for more than one
// reason; this case is the realistic shape, separate keys and issuers.
func TestATokenForOneEnvironmentFailsInAnother(t *testing.T) {
	prod := newSigner(t, "prod-key")
	test := newSigner(t, "test-key")
	tok := prod.sign(t, validClaims())
	_, err := verifier(t, test.jwks(), "https://auth.heldig.org/c/export-fish-test", "export-fish-test", now).Verify(t.Context(), tok, nonce)
	if err == nil {
		t.Fatal("a production token verified in the test environment")
	}
	if !errors.Is(err, idtoken.ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (separate keys)", err)
	}
}

type failingStore struct{}

func (failingStore) MarkUsed(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("database down")
}

func TestAStoreFailureIsNotAnAcceptance(t *testing.T) {
	s := newSigner(t, "k1")
	set, _ := idtoken.StaticKeys(s.jwks())
	v, err := idtoken.NewVerifier(idtoken.Config{Issuer: issuer, Audience: audience, Keys: set, UsedTokens: failingStore{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), s.sign(t, validClaims()), nonce); err == nil {
		t.Fatal("a token was accepted while the used-token store failed")
	}
}

func TestNewVerifierRequiresASingleUseStore(t *testing.T) {
	if _, err := idtoken.NewVerifier(idtoken.Config{Issuer: issuer, Audience: audience}); err == nil {
		t.Fatal("a verifier without a used-token store was built")
	}
}

// The remote key set refetches once on an unknown kid, which is how a key
// rotation reaches an App with no change on its side.
func TestTheRemoteKeySetPicksUpARotatedKey(t *testing.T) {
	first, second := newSigner(t, "k1"), newSigner(t, "k2")
	var mu sync.Mutex
	served := first.jwks()
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		w.Header().Set("Cache-Control", "public, max-age=600")
		_ = json.NewEncoder(w).Encode(served)
	}))
	defer srv.Close()

	v, err := idtoken.NewVerifier(idtoken.Config{
		Issuer: issuer, Audience: audience, JWKSURL: srv.URL, HTTPClient: srv.Client(),
		UsedTokens: &idtoken.MemoryUsedTokens{Now: func() time.Time { return now }}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	c := validClaims()
	if _, err := v.Verify(t.Context(), first.sign(t, c), nonce); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	served = idtoken.JWKS{Keys: append(first.jwks().Keys, second.jwks().Keys...)}
	mu.Unlock()
	c.ID = "jti-2"
	if _, err := v.Verify(t.Context(), second.sign(t, c), nonce); err != nil {
		t.Fatalf("a token under the rotated key: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if fetches != 2 {
		t.Fatalf("fetched the JWKS %d times, want 2 (initial, then once for the unknown kid)", fetches)
	}
}

func TestStaticKeysRefusesANonEd25519Key(t *testing.T) {
	_, err := idtoken.StaticKeys(idtoken.JWKS{Keys: []idtoken.JWK{{Kty: "RSA", Kid: "r"}}})
	if err == nil || !strings.Contains(err.Error(), "r") {
		t.Fatalf("err = %v, want a refusal naming the key", err)
	}
}

func remoteVerifier(t *testing.T, ks *idtoken.RemoteKeySet) *idtoken.Verifier {
	t.Helper()
	v, err := idtoken.NewVerifier(idtoken.Config{
		Issuer: issuer, Audience: audience, Keys: ks,
		UsedTokens: &idtoken.MemoryUsedTokens{Now: func() time.Time { return now }}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A JWKS that cannot be fetched is ErrKeySet, never an acceptance.
func TestAnUnavailableKeySetIsErrKeySet(t *testing.T) {
	s := newSigner(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	v := remoteVerifier(t, idtoken.NewRemoteKeySet(srv.URL, srv.Client()))
	if _, err := v.Verify(t.Context(), s.sign(t, validClaims()), nonce); !errors.Is(err, idtoken.ErrKeySet) {
		t.Fatalf("err = %v, want ErrKeySet", err)
	}
}

// An issuer that accepts the connection and never answers holds a Verify for
// FetchTimeout, not for as long as the caller's context allows.
func TestAHungKeySetFetchIsBounded(t *testing.T) {
	s := newSigner(t, "k1")
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	ks := idtoken.NewRemoteKeySet(srv.URL, srv.Client())
	ks.FetchTimeout = 50 * time.Millisecond
	v := remoteVerifier(t, ks)
	start := time.Now()
	_, err := v.Verify(context.Background(), s.sign(t, validClaims()), nonce)
	if !errors.Is(err, idtoken.ErrKeySet) {
		t.Fatalf("err = %v, want ErrKeySet", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the hung fetch held Verify for %v", took)
	}
}

// While the issuer is down, the keys last fetched still verify for StaleFor
// past their expiry, and a failed fetch is not retried on every Verify.
func TestStaleKeysAnswerWhileTheIssuerIsDown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		staleFor time.Duration
		want     error
	}{
		{"within StaleFor", 0, nil},
		{"StaleFor disabled", -1, idtoken.ErrKeySet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigner(t, "k1")
			var mu sync.Mutex
			down, fetches := false, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				fetches++
				if down {
					http.Error(w, "down", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Cache-Control", "max-age=0") // expired at once
				_ = json.NewEncoder(w).Encode(s.jwks())
			}))
			defer srv.Close()
			ks := idtoken.NewRemoteKeySet(srv.URL, srv.Client())
			ks.StaleFor = tc.staleFor
			ks.MinRefresh = time.Hour
			v := remoteVerifier(t, ks)
			c := validClaims()
			if _, err := v.Verify(t.Context(), s.sign(t, c), nonce); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			down = true
			mu.Unlock()
			for i := range 3 {
				c.ID = "jti-stale-" + string(rune('a'+i))
				if _, err := v.Verify(t.Context(), s.sign(t, c), nonce); !errors.Is(err, tc.want) {
					t.Fatalf("Verify %d while the issuer is down: %v, want %v", i, err, tc.want)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if fetches != 2 {
				t.Fatalf("fetched %d times, want 2 (the first, then one failed refresh)", fetches)
			}
		})
	}
}

// A fetch in flight (here: one an unknown kid caused, hung at the issuer)
// does not hold up a Verify whose key is already cached.
func TestACachedKeyVerifiesWhileAFetchHangs(t *testing.T) {
	known, unknown := newSigner(t, "k1"), newSigner(t, "k2")
	release := make(chan struct{})
	var mu sync.Mutex
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		n := fetches
		mu.Unlock()
		if n > 1 {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(w).Encode(known.jwks())
	}))
	defer srv.Close()
	defer close(release)
	ks := idtoken.NewRemoteKeySet(srv.URL, srv.Client())
	ks.FetchTimeout = 30 * time.Second
	v := remoteVerifier(t, ks)
	c := validClaims()
	if _, err := v.Verify(t.Context(), known.sign(t, c), nonce); err != nil {
		t.Fatal(err)
	}

	hung := make(chan error, 1)
	c.ID = "jti-unknown"
	unknownToken := unknown.sign(t, c)
	go func() { _, err := v.Verify(context.Background(), unknownToken, nonce); hung <- err }()
	for {
		mu.Lock()
		n := fetches
		mu.Unlock()
		if n > 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	done := make(chan error, 1)
	c.ID = "jti-known"
	knownToken := known.sign(t, c)
	go func() { _, err := v.Verify(context.Background(), knownToken, nonce); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a Verify with a cached key waited for the hung fetch")
	}
	select {
	case err := <-hung:
		t.Fatalf("the hung Verify returned early: %v", err)
	default:
	}
}
