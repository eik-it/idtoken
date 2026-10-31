package idtoken

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KeySet resolves a kid to the App's public key. It answers ErrUnknownKey
// (possibly wrapped) for a kid it does not hold.
type KeySet interface {
	PublicKey(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// staticKeys is a fixed key set.
type staticKeys map[string]ed25519.PublicKey

func (s staticKeys) PublicKey(_ context.Context, kid string) (ed25519.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownKey, kid)
}

// StaticKeys is a KeySet over a fixed JWKS: for tests, or an App that pins
// its keys in configuration.
func StaticKeys(set JWKS) (KeySet, error) {
	out := staticKeys{}
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("idtoken: key %q: %w", k.Kid, err)
		}
		out[k.Kid] = pub
	}
	return out, nil
}

// RemoteKeySet fetches the issuer's JWKS over HTTP and caches it for the
// server's Cache-Control max-age (ten minutes when absent). A kid it does not
// hold triggers one refetch (at most every MinRefresh), which is what lets a
// key rotation reach an App without any change on the App's side.
//
// It never stalls every Verify behind one slow issuer: a fetch is bounded by
// FetchTimeout, a Verify whose kid is in a fresh cache never waits for a
// fetch, and after a failed fetch no other is tried for MinRefresh. While a
// refresh fails, the keys last fetched still answer for StaleFor past their
// expiry. Every fetch failure wraps ErrKeySet.
type RemoteKeySet struct {
	url    string
	client *http.Client
	now    func() time.Time

	// MinRefresh is the shortest interval between two fetches caused by an
	// unknown kid, and how long a failed fetch is not retried. Zero means ten
	// seconds.
	MinRefresh time.Duration
	// FetchTimeout bounds one JWKS fetch. Zero means ten seconds.
	FetchTimeout time.Duration
	// StaleFor is how long past the cache's expiry its keys still answer
	// while refreshing fails (the issuer is down). Zero means ten minutes; a
	// negative value disables it. A key removed or revoked at the issuer
	// keeps verifying for at most this long during such an outage.
	StaleFor time.Duration

	fetching sync.Mutex // held for the length of one fetch; serializes fetches

	mu       sync.Mutex // guards the fields below; never held during a fetch
	keys     staticKeys
	expires  time.Time
	lastMiss time.Time // when an unknown kid last caused a fetch
	retryAt  time.Time // after a failed fetch, no new one before this
	lastErr  error
}

// DefaultFetchTimeout is FetchTimeout's default, and the timeout of the
// client NewRemoteKeySet makes when given none.
const DefaultFetchTimeout = 10 * time.Second

// NewRemoteKeySet reads keys from jwksURL with client (when nil, a client
// with a DefaultFetchTimeout timeout; never http.DefaultClient, which has
// none).
func NewRemoteKeySet(jwksURL string, client *http.Client) *RemoteKeySet {
	if client == nil {
		client = &http.Client{Timeout: DefaultFetchTimeout}
	}
	return &RemoteKeySet{url: jwksURL, client: client, now: time.Now}
}

const maxJWKSBytes = 1 << 20

func (r *RemoteKeySet) minRefresh() time.Duration {
	if r.MinRefresh == 0 {
		return 10 * time.Second
	}
	return r.MinRefresh
}

func (r *RemoteKeySet) PublicKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	k, have, fresh := r.cached(kid)
	if fresh && have {
		return k, nil
	}
	fetched := false
	if !fresh {
		if err := r.refresh(ctx, false); err != nil {
			if k, ok := r.stale(kid); ok {
				return k, nil
			}
			return nil, err
		}
		fetched = true
		if k, have, _ = r.cached(kid); have {
			return k, nil
		}
	}
	// An unknown kid: perhaps a rotation. One refetch per MinRefresh; a caller
	// that does not get to fetch waits out a fetch in flight and looks again.
	if !fetched && r.claimMiss() {
		if err := r.refresh(ctx, true); err != nil {
			return nil, err
		}
	} else {
		r.awaitFetch()
	}
	if k, have, _ = r.cached(kid); have {
		return k, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownKey, kid)
}

// awaitFetch returns once no fetch is in flight.
func (r *RemoteKeySet) awaitFetch() {
	r.fetching.Lock()
	defer r.fetching.Unlock()
}

// cached is kid's key from the cache, and whether the cache is fresh.
func (r *RemoteKeySet) cached(kid string) (k ed25519.PublicKey, have, fresh bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, have = r.keys[kid]
	return k, have, r.keys != nil && r.now().Before(r.expires)
}

func (r *RemoteKeySet) claimMiss() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if !r.lastMiss.IsZero() && now.Sub(r.lastMiss) < r.minRefresh() {
		return false
	}
	r.lastMiss = now
	return true
}

func (r *RemoteKeySet) stale(kid string) (ed25519.PublicKey, bool) {
	grace := r.StaleFor
	if grace == 0 {
		grace = 10 * time.Minute
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if grace < 0 || r.keys == nil || !r.now().Before(r.expires.Add(grace)) {
		return nil, false
	}
	k, ok := r.keys[kid]
	return k, ok
}

// refresh fetches the JWKS unless, once it holds the fetch lock, another
// caller has already refreshed it (force skips that check) or a failed fetch
// is too recent to retry (that failure is returned again).
func (r *RemoteKeySet) refresh(ctx context.Context, force bool) error {
	r.fetching.Lock()
	defer r.fetching.Unlock()

	r.mu.Lock()
	now := r.now()
	switch {
	case !force && r.keys != nil && now.Before(r.expires):
		r.mu.Unlock()
		return nil
	case now.Before(r.retryAt):
		err := r.lastErr
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()

	keys, ttl, err := r.fetch(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	now = r.now()
	if err != nil {
		r.lastErr, r.retryAt = err, now.Add(r.minRefresh())
		return err
	}
	r.keys, r.expires, r.lastErr, r.retryAt = keys, now.Add(ttl), nil, time.Time{}
	return nil
}

func (r *RemoteKeySet) fetch(ctx context.Context) (staticKeys, time.Duration, error) {
	timeout := r.FetchTimeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: the JWKS request: %w", ErrKeySet, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: fetching the JWKS: %w", ErrKeySet, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: fetching the JWKS: status %d", ErrKeySet, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading the JWKS: %w", ErrKeySet, err)
	}
	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, 0, fmt.Errorf("%w: decoding the JWKS: %w", ErrKeySet, err)
	}
	keys := staticKeys{}
	for _, k := range set.Keys {
		if pub, err := k.PublicKey(); err == nil {
			keys[k.Kid] = pub
		}
	}
	return keys, maxAge(resp.Header.Get("Cache-Control")), nil
}

func maxAge(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && strings.EqualFold(name, "max-age") {
			if s, err := strconv.Atoi(value); err == nil && s >= 0 && s <= 86400 {
				return time.Duration(s) * time.Second
			}
		}
	}
	return 10 * time.Minute
}
