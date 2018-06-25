package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func encrypt(pub *rsa.PublicKey, msg []byte) string {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	check(err)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decrypt(pri *rsa.PrivateKey, encoded string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	check(err)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, pri, ciphertext)
	check(err)
	return string(plaintext)
}

func loadPublicKey(filename string) *rsa.PublicKey {
	var pemData, err = ioutil.ReadFile(filename)
	check(err)

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		panic("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	check(err)

	return pub.(*rsa.PublicKey)
}

func loadPrivateKey(filename string) *rsa.PrivateKey {
	var pemData, err = ioutil.ReadFile(filename)
	check(err)

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		panic("failed to decode PEM block containing private key")
	}

	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	check(err)

	return pri
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s -k keyfile [encrypt|decrypt] string\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	keyfilePtr := flag.String("k", "", "path to key file")
	flag.Parse()
	args := flag.Args()

	if *keyfilePtr == "" {
		fmt.Fprintf(flag.CommandLine.Output(), "missing -k\n\n")
		flag.Usage()
		os.Exit(2)
	}

	if len(args) < 2 {
		flag.Usage()
		os.Exit(2)
	}

	cmd, input := args[0], args[1]
	switch cmd {
	case "encrypt":
		pub := loadPublicKey(*keyfilePtr)
		secretMessage := []byte(input)
		str := encrypt(pub, secretMessage)
		fmt.Println(str)
	case "decrypt":
		pri := loadPrivateKey(*keyfilePtr)
		str := decrypt(pri, input)
		fmt.Println(str)
	default:
		flag.Usage()
		os.Exit(2)
	}
}
