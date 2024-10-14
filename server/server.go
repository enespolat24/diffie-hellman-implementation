package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/hkdf"
)

var p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
var g *big.Int

func init() {
	// Load .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Get prime number from .env
	primeNumberStr := os.Getenv("PRIME_NUMBER")
	primeNumber, err := strconv.ParseInt(primeNumberStr, 10, 64)
	if err != nil {
		log.Fatalf("Error parsing PRIME_NUMBER: %v", err)
	}
	g = big.NewInt(primeNumber)
}

func main() {
	ln, err := net.Listen("tcp", ":17")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("Server is listening on port 17...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Generate Server Private Key
	privateKey, _ := rand.Int(rand.Reader, p)
	// Public Key Calculation: B = g^b mod p
	publicKey := new(big.Int).Exp(g, privateKey, p)

	// Read Client Public Key
	var clientPublicKeyStr string
	fmt.Fscanln(conn, &clientPublicKeyStr)
	clientPublicKey := new(big.Int)
	clientPublicKey.SetString(clientPublicKeyStr, 10)

	// Send Server Public Key to Client
	fmt.Println("Sending Public Key:", publicKey)
	fmt.Fprintf(conn, "%s\n", publicKey.String())

	// Calculate Shared Secret: S = A^b mod p
	sharedSecret := new(big.Int).Exp(clientPublicKey, privateKey, p)
	fmt.Println("Shared Secret:", sharedSecret)

	// Derive symmetric key from the shared secret
	key := deriveKey(sharedSecret.Bytes())

	// Read and decrypt 10 messages from client
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		encryptedMsg := scanner.Bytes()
		fmt.Println("Received Encrypted Message:", string(encryptedMsg))
		decryptedMsg := decryptMessage(encryptedMsg, key)
		fmt.Println("Received Decrypted Message:", string(decryptedMsg), "\n")
	}
}

// Key derivation using HKDF-SHA256
func deriveKey(secret []byte) []byte {
	hkdf := hkdf.New(sha256.New, secret, nil, nil)
	key := make([]byte, 32)
	io.ReadFull(hkdf, key)
	return key
}

// XOR decryption
func decryptMessage(message, key []byte) []byte {
	decrypted := make([]byte, len(message))
	for i := range message {
		decrypted[i] = message[i] ^ key[i%len(key)]
	}
	return decrypted
}
