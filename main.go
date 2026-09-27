// Command secretsplit — Shamir's Secret Sharing over GF(2^8) with
// verifiable shares. Educational and offline.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/efealtiparmakoglu/secretsplit/shamir"
)

const version = "1.0.0"

const usage = `secretsplit %s — split a secret into shares that need %d of them to meet again

usage:
  secretsplit split --secret <TEXT> --threshold N --shares M [--hex] [--json]
  secretsplit split --file <PATH> --threshold N --shares M
  secretsplit combine <share> <share> ... [--hex-out]
  secretsplit verify <share> ...
  secretsplit check --commitment <HEX> <share> ...

A share looks like "3-9f2ab1...": the participant number, then the
share bytes. Keep each share with a different person; the commitment is
what lets you prove a share was not altered in transit.

exit codes: 0 ok, 1 verification failed, 2 usage error
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	rawArgs := args
	fs := flag.NewFlagSet("secretsplit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	secret := fs.String("secret", "", "secret text to split")
	secretFile := fs.String("file", "", "file whose contents are the secret")
	threshold := fs.Int("threshold", 3, "shares needed to reconstruct")
	shares := fs.Int("shares", 5, "shares to produce")
	commitment := fs.String("commitment", "", "commitment to check against")
	asHex := fs.Bool("hex", false, "treat the secret as hex")
	jsonOut := fs.Bool("json", false, "JSON output")
	hexOut := fs.Bool("hex-out", false, "hex output for combine")
	help := fs.Bool("h", false, "show help")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *help || len(rawArgs) == 0 {
		fmt.Fprintf(os.Stderr, usage, version, *threshold)
		return 2
	}

	// Go's flag package stops at the first positional argument, so the
	// subcommand is taken from the raw args and only the tail is parsed.
	command := rawArgs[0]
	rest := fs.Args() // positional arguments after the flags

	switch command {
	case "split":
		return cmdSplit(*secret, *secretFile, *asHex, *threshold, *shares, *jsonOut)
	case "combine":
		return cmdCombine(rest, *hexOut, *jsonOut)
	case "verify":
		return cmdVerify(rest)
	case "check":
		return cmdCheck(rest, *commitment, *threshold)
	default:
		fmt.Fprintf(os.Stderr, "secretsplit: unknown command %q\n", command)
		return 2
	}
}

func cmdSplit(secret, file string, asHex bool, threshold, shares int, jsonOut bool) int {
	var data []byte
	switch {
	case secret != "":
		if asHex {
			decoded, err := hex.DecodeString(secret)
			if err != nil {
				fmt.Fprintf(os.Stderr, "secretsplit: --secret is not valid hex: %v\n", err)
				return 2
			}
			data = decoded
		} else {
			data = []byte(secret)
		}
	case file != "":
		contents, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
			return 1
		}
		data = contents
	default:
		fmt.Fprintln(os.Stderr, "secretsplit: split needs --secret or --file")
		return 2
	}

	result, err := secretsplit.SplitSecret(data, threshold, shares, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
		return 2
	}
	secretsplit.SortShares(result.Shares)

	if jsonOut {
		fmt.Printf("{\"threshold\": %d, \"shares\": %d, \"length\": %d, \"commitment\": \"%s\", \"shares_data\": [",
			result.Threshold, len(result.Shares), result.Length, result.Commitment)
		for i, share := range result.Shares {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("\"%s\"", secretsplit.FormatShare(share))
		}
		fmt.Println("]}")
		return 0
	}

	fmt.Printf("secret: %d bytes, split into %d shares, %d needed to combine\n",
		result.Length, len(result.Shares), result.Threshold)
	fmt.Printf("commitment: %s\n", result.Commitment)
	fmt.Println("shares (one line each — hand them out separately):")
	for _, share := range result.Shares {
		fmt.Printf("  %s\n", secretsplit.FormatShare(share))
	}
	return 0
}

func parseShares(inputs []string) ([]secretsplit.Share, error) {
	if len(inputs) == 0 {
		return nil, secretsplit.ErrNoShares
	}
	var shares []secretsplit.Share
	for _, input := range inputs {
		share, err := secretsplit.ParseShare(strings.TrimSpace(input))
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func cmdCombine(inputs []string, hexOut, jsonOut bool) int {
	shares, err := parseShares(inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
		return 2
	}
	// the threshold is simply how many shares we were handed
	secret, err := secretsplit.Combine(shares, len(shares))
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
		return 1
	}
	if jsonOut {
		fmt.Printf("{\"secret_hex\": \"%s\"}\n", hex.EncodeToString(secret))
		return 0
	}
	if hexOut {
		fmt.Println(hex.EncodeToString(secret))
		return 0
	}
	os.Stdout.Write(secret)
	fmt.Println()
	return 0
}

func cmdVerify(inputs []string) int {
	shares, err := parseShares(inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
		return 2
	}
	bad := 0
	for _, share := range shares {
		if err := secretsplit.VerifyShare(share); err != nil {
			fmt.Printf("share %d: FAILED (%v)\n", share.Index, err)
			bad++
			continue
		}
		fmt.Printf("share %d: intact\n", share.Index)
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func cmdCheck(inputs []string, commitment string, threshold int) int {
	if commitment == "" {
		fmt.Fprintln(os.Stderr, "secretsplit: check needs --commitment")
		return 2
	}
	shares, err := parseShares(inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
		return 2
	}
	if err := secretsplit.VerifyCommitment(shares, threshold, commitment); err != nil {
		if errors.Is(err, secretsplit.ErrNotEnoughShares) {
			fmt.Fprintf(os.Stderr, "secretsplit: %v\n", err)
			return 2
		}
		fmt.Printf("FAILED: %v\n", err)
		return 1
	}
	fmt.Println("OK: these shares match the published commitment")
	return 0
}
