package secretsplit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
)

// Share is one participant's piece: the value of a random polynomial at
// the share's index. Checksum detects transcription and storage damage.
type Share struct {
	Index    int
	Data     []byte
	Checksum string // hex SHA-256 over index and data
}

// Split is the result of a split operation.
type Split struct {
	Shares     []Share
	Threshold  int
	Commitment string // hex SHA-256 over the polynomial coefficients
	Length     int    // secret length in bytes
}

var (
	ErrNotEnoughShares = errors.New("not enough shares to reconstruct")
	ErrNoShares        = errors.New("no shares given")
	ErrDuplicateIndex  = errors.New("duplicate share index")
	ErrBadIndex        = errors.New("share index out of range 1..255")
	ErrChecksum        = errors.New("share checksum mismatch")
	ErrCommitment      = errors.New("commitment mismatch: shares are not from one split")
)

type rng interface {
	Read(p []byte) (int, error)
}

// cryptoRand is the default randomness source.
type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }

// SplitSecret turns secret into n shares, threshold of which suffice.
// Each byte of the secret gets its own random polynomial over GF(2^8).
func SplitSecret(secret []byte, threshold, n int, source io.Reader) (Split, error) {
	if len(secret) == 0 {
		return Split{}, errors.New("secret is empty")
	}
	if threshold < 1 {
		return Split{}, errors.New("threshold must be at least 1")
	}
	if n < threshold {
		return Split{}, errors.New("cannot have fewer shares than the threshold")
	}
	if n > 255 {
		return Split{}, errors.New("at most 255 shares (GF(2^8) has 255 points)")
	}
	if source == nil {
		source = cryptoRand{}
	}

	// One polynomial per secret byte, coefficients ordered a_0, a_1, ..., so
	// Horner evaluation at x=0 yields the secret byte itself.
	leading := make([]byte, len(secret)*(threshold-1))
	if _, err := io.ReadFull(source, leading); err != nil {
		return Split{}, fmt.Errorf("read randomness: %w", err)
	}
	coeffs := make([]byte, len(secret)*threshold)
	for i := 0; i < len(secret); i++ {
		row := coeffs[i*threshold : (i+1)*threshold]
		row[0] = secret[i] // a_0: the secret byte
		copy(row[1:], leading[i*(threshold-1):(i+1)*(threshold-1)])
	}
	coefficients := make([][]byte, len(secret))
	for i := range coefficients {
		coefficients[i] = coeffs[i*threshold : (i+1)*threshold]
	}

	shares := make([]Share, n)
	for participant := 1; participant <= n; participant++ {
		x := byte(participant)
		data := make([]byte, len(secret))
		for byteIndex, row := range coefficients {
			// Horner evaluation of the polynomial at x
			acc := row[len(row)-1]
			for i := len(row) - 2; i >= 0; i-- {
				acc = Add(Mul(acc, x), row[i])
			}
			data[byteIndex] = acc
		}
		shares[participant-1] = Share{
			Index: participant,
			Data:  data,
		}
		shares[participant-1].Checksum = checksumOf(shares[participant-1])
	}

	return Split{
		Shares:     shares,
		Threshold:  threshold,
		Commitment: commitmentOf(coefficients),
		Length:     len(secret),
	}, nil
}

// Combine reconstructs the secret from any threshold or more shares.
func Combine(shares []Share, threshold int) ([]byte, error) {
	if len(shares) == 0 {
		return nil, ErrNoShares
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrNotEnoughShares, len(shares), threshold)
	}
	seen := map[int]bool{}
	for _, share := range shares {
		if share.Index < 1 || share.Index > 255 {
			return nil, fmt.Errorf("%w: %d", ErrBadIndex, share.Index)
		}
		if seen[share.Index] {
			return nil, fmt.Errorf("%w: %d", ErrDuplicateIndex, share.Index)
		}
		seen[share.Index] = true
		if share.Checksum != "" && share.Checksum != checksumOf(share) {
			return nil, fmt.Errorf("%w: share %d", ErrChecksum, share.Index)
		}
	}

	length := len(shares[0].Data)
	for _, share := range shares[1:] {
		if len(share.Data) != length {
			return nil, errors.New("shares have inconsistent lengths")
		}
	}

	used := shares[:threshold] // any threshold subset works
	secret := make([]byte, length)
	for byteIndex := 0; byteIndex < length; byteIndex++ {
		secret[byteIndex] = interpolate(used, byteIndex)
	}
	return secret, nil
}

// interpolate evaluates the degree threshold-1 polynomial through the
// first `threshold` points using Lagrange interpolation in GF(2^8).
func interpolate(shares []Share, byteIndex int) byte {
	var result byte
	for i, si := range shares {
		xi := byte(si.Index)
		var basis byte = 1
		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := byte(sj.Index)
			// basis *= (0 - xj) / (xi - xj); in GF(2^8), -x == x
			basis = Mul(basis, Div(xj, Add(xi, xj)))
		}
		result = Add(result, Mul(si.Data[byteIndex], basis))
	}
	return result
}

// VerifyShare checks a single share against its own checksum.
func VerifyShare(share Share) error {
	if share.Checksum == "" {
		return nil // checksum optional
	}
	if share.Checksum != checksumOf(share) {
		return fmt.Errorf("%w: share %d", ErrChecksum, share.Index)
	}
	return nil
}

// VerifyCommitment recomputes the polynomial coefficients from any
// threshold shares and compares the resulting hash to the published one.
// A mismatch means the shares did not come from the same split, or one of
// them was altered.
func VerifyCommitment(shares []Share, threshold int, commitment string) error {
	if len(shares) < threshold {
		return fmt.Errorf("%w: have %d, need %d", ErrNotEnoughShares, len(shares), threshold)
	}
	used := shares[:threshold]
	length := len(used[0].Data)
	for _, share := range used {
		if len(share.Data) != length {
			return errors.New("shares have inconsistent lengths")
		}
	}
	coefficients := make([][]byte, length)

	xs := make([]byte, threshold)
	for i, share := range used {
		xs[i] = byte(share.Index)
	}
	ys := make([]byte, threshold)
	for byteIndex := 0; byteIndex < length; byteIndex++ {
		for i, share := range used {
			ys[i] = share.Data[byteIndex]
		}
		row, err := solveCoefficients(xs, ys)
		if err != nil {
			return err
		}
		coefficients[byteIndex] = row
	}
	if commitmentOf(coefficients) != commitment {
		return ErrCommitment
	}
	return nil
}

// solveCoefficients recovers a_0..a_{n-1} from n points by Gaussian
// elimination on the Vandermonde system sum_j x_i^j * a_j = y_i.
func solveCoefficients(xs, ys []byte) ([]byte, error) {
	n := len(xs)
	matrix := make([][]byte, n)
	for i := 0; i < n; i++ {
		row := make([]byte, n+1)
		power := byte(1)
		for j := 0; j < n; j++ {
			row[j] = power
			power = Mul(power, xs[i])
		}
		row[n] = ys[i]
		matrix[i] = row
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for row := col; row < n; row++ {
			if matrix[row][col] != 0 {
				pivot = row
				break
			}
		}
		if pivot == -1 {
			return nil, fmt.Errorf("%w: share points are not distinct", ErrBadIndex)
		}
		matrix[col], matrix[pivot] = matrix[pivot], matrix[col]

		inv := Inv(matrix[col][col])
		for c := col; c <= n; c++ {
			matrix[col][c] = Mul(matrix[col][c], inv)
		}
		for row := 0; row < n; row++ {
			if row == col || matrix[row][col] == 0 {
				continue
			}
			factor := matrix[row][col]
			for c := col; c <= n; c++ {
				matrix[row][c] = Add(matrix[row][c], Mul(factor, matrix[col][c]))
			}
		}
	}
	coefficients := make([]byte, n)
	for i := 0; i < n; i++ {
		coefficients[i] = matrix[i][n]
	}
	return coefficients, nil
}

func checksumOf(share Share) string {
	hash := sha256.New()
	hash.Write([]byte{byte(share.Index)})
	hash.Write(share.Data)
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

func commitmentOf(coefficients [][]byte) string {
	hash := sha256.New()
	for _, row := range coefficients {
		hash.Write(row)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// FormatShare renders a share as the copy-pasteable "index-hex" form.
func FormatShare(share Share) string {
	return fmt.Sprintf("%d-%s", share.Index, hex.EncodeToString(share.Data))
}

// ParseShare parses the "index-hex" form produced by FormatShare.
func ParseShare(text string) (Share, error) {
	var share Share
	dash := -1
	for i, r := range text {
		if r == '-' {
			dash = i
			break
		}
	}
	if dash <= 0 || dash == len(text)-1 {
		return share, fmt.Errorf("share %q: want index-hex", text)
	}
	index, err := parseInt(text[:dash])
	if err != nil || index < 1 || index > 255 {
		return share, fmt.Errorf("share %q: bad index", text)
	}
	data, err := hex.DecodeString(text[dash+1:])
	if err != nil {
		return share, fmt.Errorf("share %q: %w", text, err)
	}
	share = Share{Index: index, Data: data}
	share.Checksum = checksumOf(share)
	return share, nil
}

func parseInt(s string) (int, error) {
	value, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return 0, errors.New("not a number")
	}
	return int(value.Int64()), nil
}

// SortShares orders shares by index so output is deterministic.
func SortShares(shares []Share) {
	sort.Slice(shares, func(i, j int) bool { return shares[i].Index < shares[j].Index })
}
