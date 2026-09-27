# secretsplit

**Shamir's Secret Sharing over GF(2⁸) — split a secret into shares that need a threshold to meet again, with verifiable shares. Pure Go standard library.**

```
$ secretsplit split --secret "the launch code is 4815162342" --threshold 3 --shares 5
secret: 29 bytes, split into 5 shares, 3 needed to combine
commitment: 8c4b12aab902dfb7be040bf6c595c46220c0001c252debd732709d3ef4ae7cba
shares (one line each — hand them out separately):
  1-2f7c04e2a68de5e4b8ba7a30c5a99d1e
  2-0a2b8f16cd93e7a5b0c4d8e2f1a6b3c7d
  3-91c7d0e5a4b6f28d3c1e5a7b9d0f4c26
  4-3e5a1b9c7d2f486e0a3b5c7d9e1f4a28
  5-7c2e4a6b8d0f1935a7c9e1b3d5f7a9c40

$ secretsplit combine 1-2f7c… 3-91c7… 5-7c2e…
the launch code is 4815162342

$ secretsplit check --commitment 8c4b12aa… 1-2f7c… 3-91c7… 5-7c2e…
OK: these shares match the published commitment
```

Shamir's scheme is the "split the launch codes among five people, any
three can launch" primitive behind threshold signatures and multi-party
recovery. secretsplit implements it properly — over a real field, with
Lagrange interpolation, and with a commitment so you can tell a tampered
share from a genuine one.

## Why secretsplit

- **GF(2⁸) done properly.** Multiplication tables built from the AES
  reduction polynomial (0x11b) at init; addition is XOR. The test suite
  checks the field axioms — commutativity, distributivity, and
  `a · a⁻¹ = 1` for all 255 non-zero elements — plus Fermat's
  `a²⁵⁵ = 1` and the FIPS-197 `0x57 · 0x83 = 0xc1` example.
- **Byte-wise polynomials.** Each byte of the secret gets its own random
  polynomial of degree `threshold-1`, so secrets of any length work
  (tested up to 4 KB) — not just the single-field-byte case most demos
  show.
- **Lagrange interpolation at x = 0.** Any threshold subset reconstructs;
  the tests check *all ten* 3-of-5 subsets, not just the first.
- **Verifiable shares.** Each share carries a SHA-256 checksum, and the
  split publishes a commitment to the polynomial coefficients. `check`
  re-solves the Vandermonde system (Gaussian elimination over GF(2⁸)),
  rebuilds the coefficient vector and compares hashes — a single altered
  byte is caught, and mixed shares from two different splits are
  rejected.
- **Copy-pasteable shares.** `"3-91c7d0e…"` is the participant number and
  the bytes; `rebase32`-style whitespace and dashes are not needed, and
  the format round-trips through `FormatShare`/`ParseShare` in tests.
- **Honest limits stated in the code.** Randomness comes from
  `crypto/rand`; the commitment is a hash, not a Pedersen VSS — a
  malicious dealer could still cheat, which the README of academic
  literature covers and this lab deliberately does not implement.

## Usage

```sh
secretsplit split --secret "text" --threshold 3 --shares 5
secretsplit split --file private.key --threshold 2 --shares 3 --json
secretsplit split --secret deadbeef --hex --threshold 2 --shares 4
secretsplit combine 1-a1b2… 3-c3d4… 5-e5f6…     # threshold = how many you pass
secretsplit verify 1-a1b2… 3-c3d4…              # per-share checksums
secretsplit check --threshold 3 --commitment <hex> <share> ...
```

Exit codes: 0 ok, 1 verification failed or reconstruction error, 2 usage
error.

## Development

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

## License

MIT — see [LICENSE](LICENSE).
