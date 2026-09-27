package secretsplit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// readerFunc adapts a function to io.Reader for deterministic tests.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func mustSplit(t *testing.T, secret string, threshold, shares int) Split {
	t.Helper()
	result, err := SplitSecret([]byte(secret), threshold, shares, nil)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return result
}

func TestFieldAxioms(t *testing.T) {
	if Mul(0x57, 0x83) != 0xc1 { // FIPS-197 §4.2 worked example
		t.Errorf("0x57*0x83 = %#x, want 0xc1", Mul(0x57, 0x83))
	}
	if Mul(0x57, 0x13) != 0xfe {
		t.Errorf("0x57*0x13 = %#x, want 0xfe", Mul(0x57, 0x13))
	}
	for a := 0; a < 256; a++ {
		if Mul(byte(a), 0) != 0 {
			t.Fatalf("a*0 != 0 for a=%d", a)
		}
		if Mul(byte(a), 1) != byte(a) {
			t.Fatalf("a*1 != a for a=%d", a)
		}
		if a != 0 {
			if Mul(byte(a), Inv(byte(a))) != 1 {
				t.Fatalf("a*inv(a) != 1 for a=%d", a)
			}
		}
		for _, b := range []int{0x00, 0x01, 0x7f, 0x80, 0xff} {
			x, y := byte(a), byte(b)
			if Mul(x, y) != Mul(y, x) {
				t.Fatalf("multiplication not commutative at %d,%d", a, b)
			}
			if Add(x, y) != Add(y, x) {
				t.Fatalf("addition not commutative at %d,%d", a, b)
			}
		}
	}
}

func TestFieldDistributivity(t *testing.T) {
	for i := 0; i < 200; i++ {
		a, b, c := byte(i*7+1), byte(i*13+2), byte(i*29+3)
		if Mul(a, Add(b, c)) != Add(Mul(a, b), Mul(a, c)) {
			t.Fatalf("distributivity failed at a=%#x b=%#x c=%#x", a, b, c)
		}
	}
}

func TestDivAndPow(t *testing.T) {
	if Div(0xc1, 0x57) != 0x83 {
		t.Errorf("0xc1/0x57 = %#x, want 0x83", Div(0xc1, 0x57))
	}
	if Div(5, 0) != 0 {
		t.Error("division by zero must be defined as 0")
	}
	if Pow(2, 0) != 1 {
		t.Error("a^0 must be 1")
	}
	// 2^8 = 256 = 0x11B - 0x100 = 0x1B, the same reduction AES uses
	if Pow(2, 8) != 0x1B {
		t.Errorf("2^8 = %#x, want 0x1b", Pow(2, 8))
	}
	// Fermat in GF(2^8): a^255 = 1 for a != 0
	for _, a := range []byte{1, 2, 0x57, 0xff} {
		if Pow(a, 255) != 1 {
			t.Errorf("a^255 != 1 for a=%#x", a)
		}
	}
}

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := "the quick brown fox jumps over the lazy dog"
	result := mustSplit(t, secret, 3, 5)
	if len(result.Shares) != 5 {
		t.Fatalf("shares = %d", len(result.Shares))
	}
	if result.Length != len(secret) {
		t.Errorf("length = %d, want %d", result.Length, len(secret))
	}
	// every 3-of-5 subset must reconstruct
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				subset := []Share{result.Shares[i], result.Shares[j], result.Shares[k]}
				got, err := Combine(subset, 3)
				if err != nil {
					t.Fatalf("combine %d,%d,%d: %v", i, j, k, err)
				}
				if string(got) != secret {
					t.Fatalf("combine %d,%d,%d = %q", i, j, k, got)
				}
			}
		}
	}
}

func TestBinarySecretRoundTrip(t *testing.T) {
	secret := []byte{0x00, 0xff, 0x7f, 0x80, 0x01, 0x00, 0x00, 0xfe}
	result, err := SplitSecret(secret, 2, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(result.Shares[:2], 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("binary round trip: %x != %x", got, secret)
	}
}

func TestTooFewSharesFails(t *testing.T) {
	result := mustSplit(t, "secret", 3, 5)
	if _, err := Combine(result.Shares[:2], 3); !errors.Is(err, ErrNotEnoughShares) {
		t.Errorf("err = %v, want ErrNotEnoughShares", err)
	}
}

func TestNoSharesFails(t *testing.T) {
	if _, err := Combine(nil, 3); !errors.Is(err, ErrNoShares) {
		t.Errorf("err = %v, want ErrNoShares", err)
	}
}

func TestDuplicateIndexRejected(t *testing.T) {
	result := mustSplit(t, "secret", 2, 3)
	dup := []Share{result.Shares[0], result.Shares[0]}
	if _, err := Combine(dup, 2); !errors.Is(err, ErrDuplicateIndex) {
		t.Errorf("err = %v, want ErrDuplicateIndex", err)
	}
}

func TestBadIndexRejected(t *testing.T) {
	result := mustSplit(t, "secret", 2, 3)
	bad := []Share{result.Shares[0], {Index: 0, Data: result.Shares[1].Data}}
	if _, err := Combine(bad, 2); !errors.Is(err, ErrBadIndex) {
		t.Errorf("err = %v, want ErrBadIndex", err)
	}
}

func TestShareChecksumDetectsDamage(t *testing.T) {
	result := mustSplit(t, "secret value", 2, 3)
	share := result.Shares[1]
	if err := VerifyShare(share); err != nil {
		t.Fatalf("intact share failed: %v", err)
	}
	damaged := share
	damaged.Data = append([]byte{}, share.Data...)
	damaged.Data[0] ^= 0xFF
	if err := VerifyShare(damaged); !errors.Is(err, ErrChecksum) {
		t.Errorf("err = %v, want ErrChecksum", err)
	}
	if _, err := Combine([]Share{damaged, result.Shares[2]}, 2); !errors.Is(err, ErrChecksum) {
		t.Errorf("combine err = %v, want ErrChecksum", err)
	}
}

func TestCommitmentVerification(t *testing.T) {
	result := mustSplit(t, "verified secret", 3, 5)
	subset := result.Shares[:3]
	if err := VerifyCommitment(subset, 3, result.Commitment); err != nil {
		t.Errorf("valid shares failed commitment: %v", err)
	}
	// any threshold subset of the same split also verifies
	if err := VerifyCommitment([]Share{result.Shares[1], result.Shares[3], result.Shares[4]}, 3, result.Commitment); err != nil {
		t.Errorf("other valid subset failed: %v", err)
	}
}

func TestCommitmentDetectsMixedSplits(t *testing.T) {
	first := mustSplit(t, "secret one", 2, 4)
	second := mustSplit(t, "secret two", 2, 4)
	mixed := []Share{first.Shares[0], second.Shares[1]}
	if err := VerifyCommitment(mixed, 2, first.Commitment); !errors.Is(err, ErrCommitment) {
		t.Errorf("err = %v, want ErrCommitment", err)
	}
	if err := VerifyCommitment(mixed, 2, second.Commitment); !errors.Is(err, ErrCommitment) {
		t.Errorf("err = %v, want ErrCommitment (second)", err)
	}
}

func TestMismatchedLengthsRejected(t *testing.T) {
	result := mustSplit(t, "abc", 2, 3)
	long := result.Shares[0]
	long.Data = append(append([]byte{}, long.Data...), 0x00)

	if _, err := Combine([]Share{long, result.Shares[1]}, 2); err == nil {
		t.Error("Combine should reject mismatched share lengths")
	}
	if err := VerifyCommitment([]Share{long, result.Shares[1]}, 2, result.Commitment); err == nil {
		t.Error("VerifyCommitment should reject mismatched share lengths")
	}
}

func TestCommitmentNeedsThreshold(t *testing.T) {
	result := mustSplit(t, "secret", 3, 5)
	if err := VerifyCommitment(result.Shares[:2], 3, result.Commitment); !errors.Is(err, ErrNotEnoughShares) {
		t.Errorf("err = %v, want ErrNotEnoughShares", err)
	}
}

func TestSplitValidation(t *testing.T) {
	cases := []struct {
		name              string
		secret            string
		threshold, shares int
	}{
		{"empty secret", "", 2, 3},
		{"zero threshold", "x", 0, 3},
		{"shares below threshold", "x", 4, 3},
		{"too many shares", "x", 2, 300},
	}
	for _, c := range cases {
		if _, err := SplitSecret([]byte(c.secret), c.threshold, c.shares, nil); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestThresholdOneIsJustTheSecret(t *testing.T) {
	secret := "one share is enough"
	result := mustSplit(t, secret, 1, 3)
	got, err := Combine(result.Shares[:1], 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Errorf("threshold 1 gave %q", got)
	}
}

func TestThresholdEqualsShares(t *testing.T) {
	secret := "everyone must show up"
	result := mustSplit(t, secret, 4, 4)
	got, err := Combine(result.Shares, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Errorf("got %q", got)
	}
	if _, err := Combine(result.Shares[:3], 4); !errors.Is(err, ErrNotEnoughShares) {
		t.Error("missing a share must fail")
	}
}

func TestSplitsDifferEachTime(t *testing.T) {
	secret := "same secret, different shares"
	first := mustSplit(t, secret, 2, 3)
	second := mustSplit(t, secret, 2, 3)
	if bytes.Equal(first.Shares[0].Data, second.Shares[0].Data) {
		t.Error("two splits produced identical shares")
	}
	if first.Commitment == second.Commitment {
		t.Error("two splits produced the same commitment")
	}
}

func TestDeterministicReaderProducesSameSplit(t *testing.T) {
	reader := readerFunc(func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i + 1)
		}
		return len(b), nil
	})
	secret := []byte("deterministic")
	first, err := SplitSecret(secret, 3, 5, reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SplitSecret(secret, 3, 5, reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Shares[2].Data, second.Shares[2].Data) {
		t.Error("same randomness should give the same share")
	}
	got, err := Combine(first.Shares[:3], 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("round trip with fixed randomness: %q", got)
	}
}

func TestFormatAndParseRoundTrip(t *testing.T) {
	result := mustSplit(t, "parse me", 2, 3)
	for _, share := range result.Shares {
		text := FormatShare(share)
		parsed, err := ParseShare(text)
		if err != nil {
			t.Fatalf("parse %q: %v", text, err)
		}
		if parsed.Index != share.Index || !bytes.Equal(parsed.Data, share.Data) {
			t.Errorf("round trip mismatch for %q", text)
		}
		if err := VerifyShare(parsed); err != nil {
			t.Errorf("parsed share fails its own checksum: %v", err)
		}
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, input := range []string{"", "1-", "-ff", "0-ff", "256-ff", "1-zz", "nope"} {
		if _, err := ParseShare(input); err == nil {
			t.Errorf("ParseShare(%q) should fail", input)
		}
	}
}

func TestSortShares(t *testing.T) {
	result := mustSplit(t, "sort me", 2, 5)
	SortShares(result.Shares)
	for i, share := range result.Shares {
		if share.Index != i+1 {
			t.Fatalf("position %d holds index %d", i, share.Index)
		}
	}
}

func TestLongSecret(t *testing.T) {
	secret := make([]byte, 4096)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	result, err := SplitSecret(secret, 3, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(result.Shares[1:4], 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("4 KB secret did not round trip")
	}
}
