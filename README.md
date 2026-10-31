# idtoken

Verifies ID tokens issued by magic-auth, the email sign-in service for EIK IT
apps. Standard library only, Go 1.24 or later.

```
go get github.com/eik-it/idtoken
```

## Use

```go
v, err := idtoken.NewVerifier(idtoken.Config{
	Issuer:     "https://auth.heldig.org/c/export-fish",
	Audience:   "export-fish",
	UsedTokens: store, // MarkUsed(ctx, jti, expiresAt) (first bool, err error)
})
claims, err := v.Verify(ctx, r.URL.Query().Get("id_token"), nonce)
```

`Verify` checks:

- the EdDSA (Ed25519) signature against the App's JWKS, following key rotation;
- `iss`, `aud`, `exp` (at most two minutes after `iat`) and `nonce`;
- that `jti` has not been used, through your `UsedTokens` store, so a token is
  accepted at most once.

A database table with a unique `jti` column is enough for `UsedTokens`, as long
as each row is kept until its `expiresAt`. `MemoryUsedTokens` is correct only
for an App that runs as one process.

Every failure wraps one of the `Err*` sentinels (test with `errors.Is`), except
a failure of your own store, which is returned wrapped and is never an
acceptance.

## Why not a generic OIDC library

magic-auth returns the token in the redirect URI's **query string**, not the
fragment. Generic OpenID Connect clients reject that response.

## Claims

`sub` is a stable UUID per person, the same for every App: key users on it.
`email` is the confirmed address at sign-in time (`email_verified` is always
true) and can change.

## Tests in your App

`Sign` and `PublicJWK` are exported so an App's own tests can mint tokens and
serve a JWKS without a running magic-auth.
