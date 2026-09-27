// Package shamir implements Shamir's Secret Sharing over GF(2^8) with
// verifiable shares. Educational: the randomness comes from crypto/rand
// and the arithmetic is field-correct, but this is a teaching tool.
package secretsplit

// GF(2^8) arithmetic with the AES reduction polynomial 0x11b.

var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		x = gmulSlow(x, 3) // multiply by the generator 3 (x + 1)
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gmulSlow(a, b byte) byte {
	product := 0
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			product ^= int(a)
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return byte(product)
}

// Add is XOR in GF(2^8) — the field's addition.
func Add(a, b byte) byte { return a ^ b }

// Mul multiplies in GF(2^8).
func Mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// Div divides in GF(2^8); dividing by zero yields 0 (callers must not).
func Div(a, b byte) byte {
	if b == 0 || a == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

// Inv is the multiplicative inverse of a.
func Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// Pow raises a to the given exponent.
func Pow(a byte, e int) byte {
	if e == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	result := byte(1)
	base := a
	for e > 0 {
		if e&1 == 1 {
			result = Mul(result, base)
		}
		base = Mul(base, base)
		e >>= 1
	}
	return result
}
