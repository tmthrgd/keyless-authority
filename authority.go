package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"

	"github.com/mitchellh/go-homedir"
)

func main() {
	flag := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var privatePath string
	flag.StringVar(&privatePath, "private", "~/.keyless-authority.key", "the path to the private key")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
	%[1]s generate-authority
	%[1]s sign
	%[1]s generate
	%[1]s public-key
`, os.Args[0])

		fmt.Fprintln(os.Stderr, "Top-level flags:")
		flag.PrintDefaults()
	}

	if len(os.Args) < 2 || len(os.Args[1]) == 0 {
		fmt.Fprintln(os.Stderr, "No command is given.")
		flag.Usage()
		os.Exit(1)
	}

	flag.Parse(os.Args[2:])

	privatePath, err := homedir.Expand(privatePath)
	if err != nil {
		panic(err)
	}

	if os.Args[1] == "generate-authority" {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		if err = ioutil.WriteFile(privatePath, privateKey, 0600); err != nil {
			panic(err)
		}

		fmt.Println(base64.RawStdEncoding.EncodeToString(publicKey))
		return
	}

	privateKey, err := ioutil.ReadFile(privatePath)
	if err != nil {
		panic(err)
	}

	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)

	switch os.Args[1] {
	case "sign":
		toSign, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}

		sig := ed25519.Sign(privateKey, toSign)

		os.Stdout.Write(sig)
	case "generate":
		newPublic, newPrivate, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		sig := ed25519.Sign(privateKey, newPublic)

		id := sha256.Sum256(publicKey)

		os.Stdout.Write(newPrivate)
		os.Stdout.Write(id[:8])
		os.Stdout.Write(sig)
	case "public-key":
		fmt.Println(base64.RawStdEncoding.EncodeToString(publicKey))
	default:
		fmt.Fprintln(os.Stderr, "Unkown command given.")
		flag.Usage()
		os.Exit(1)
	}
}
