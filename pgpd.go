package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

var (
	app           = flag.NewFlagSet("pgpd", flag.ExitOnError)
	readFilename  = app.String("in", "-", "Input file (defaults to stdin)")
	writeFilename = app.String("out", "-", "Output file (defaults to stdout)")
	pkeyFilename  = app.String("pkey", "", "Private key file")
	passphrase    = app.String("pass", "", "Private key decryption passphrase")
)

func openFileOrStdin(filename string) (io.ReadCloser, error) {
	if filename == "-" {
		return os.Stdin, nil
	}
	return os.Open(filename)
}

func createFileOrStdout(filename string) (io.WriteCloser, error) {
	if filename == "" {
		return nil, fmt.Errorf("cannot create file with no name")
	}
	if filename == "-" {
		return os.Stdout, nil
	}
	return os.Create(filename)
}

func main() {
	if err := app.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	log.Printf("Using private key: %s", *pkeyFilename)
	ring, err := DecodePrivateKeyFileRing(*pkeyFilename, []byte(*passphrase))
	if err != nil {
		panic(err)
	}

	log.Printf("Reading file: %s", *readFilename)
	in, err := openFileOrStdin(*readFilename)
	if err != nil {
		panic(err)
	}
	defer in.Close()

	log.Printf("Writitng to file: %s", *writeFilename)
	out, err := createFileOrStdout(*writeFilename)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	md, err := openpgp.ReadMessage(in, ring, nil, nil)
	if err != nil {
		panic(err)
	}

	if n, err := io.Copy(out, md.UnverifiedBody); err != nil {
		panic(err)
	} else {
		log.Printf("Wrote %d bytes to output", n)
	}
}

func DecodePrivateKeyFileRing(filename string, passphrase []byte) (openpgp.EntityList, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kr, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}

	for _, key := range kr.DecryptionKeys() {
		if key.PrivateKey.Encrypted {
			if err := key.PrivateKey.Decrypt(passphrase); err != nil {
				return nil, err
			}
		}
	}

	return kr, nil
}
