package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	privateKeyOutput := flag.String("private-key-out", "", "new private key output path")
	flag.Parse()
	if strings.TrimSpace(*privateKeyOutput) == "" {
		fail("-private-key-out is required")
	}
	if _, err := os.Lstat(*privateKeyOutput); err == nil || !os.IsNotExist(err) {
		fail("private key output must not exist")
	}
	if err := os.MkdirAll(filepath.Dir(*privateKeyOutput), 0o700); err != nil {
		fail("create private key directory: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("generate key: %v", err)
	}
	encodedPrivate := base64.StdEncoding.EncodeToString(privateKey) + "\n"
	if err := os.WriteFile(*privateKeyOutput, []byte(encodedPrivate), 0o600); err != nil {
		fail("write private key: %v", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(publicKey))
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
