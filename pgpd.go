package main

import (
	"flag"
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

func main() {
	if err := app.Parse(os.Args[1:]); err != nil {
		log.Fatalf("Failed to parse arguments: %s", err)
	}

	if *pkeyFilename == "" {
		log.Fatal("Missing private key")
	}
	ring, err := decodePrivateKeyFileRing(*pkeyFilename, []byte(*passphrase))
	if err != nil {
		log.Fatalf("Unable to read private key: %s", err)
	}

	if *readFilename == "" {
		log.Fatal("Missing input filename")
	}
	in, err := openFileOrStdin(*readFilename)
	if err != nil {
		log.Fatalf("Unable to open input file: %s", err)
	}
	defer in.Close()

	if *writeFilename == "" {
		log.Fatal("Missing output filename")
	}
	out, err := createFileOrStdout(*writeFilename)
	if err != nil {
		log.Fatalf("Unable to open output file: %s", err)
	}
	defer out.Close()

	md, err := openpgp.ReadMessage(in, ring, nil, nil)
	if err != nil {
		log.Fatalf("Failed to decode input file: %s", err)
	}

	if n, err := io.Copy(out, md.UnverifiedBody); err != nil {
		log.Fatalf("Error copying decoded input to output: %s", err)
	} else {
		log.Printf("Wrote %d bytes to output", n)
	}
}

func decodePrivateKeyFileRing(filename string, passphrase []byte) (openpgp.EntityList, error) {
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

func openFileOrStdin(filename string) (io.ReadCloser, error) {
	if filename == "-" {
		return os.Stdin, nil
	}
	return os.Open(filename)
}

func createFileOrStdout(filename string) (io.WriteCloser, error) {
	if filename == "-" {
		return os.Stdout, nil
	}
	return os.Create(filename)
}
