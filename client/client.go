package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/hkdf"
)

var p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
var g = new(big.Int)
var strings = []string{"Hello", "World", "This", "Is", "A", "Test", "With", "10", "Strings", "!!!!!"}

func main() {
	//load env
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file", err)
	}

	primeNumber := os.Getenv("PRIME_NUMBER")
	if _, ok := g.SetString(primeNumber, 10); !ok {
		log.Fatalf("Error parsing PRIME_NUMBER: %v", primeNumber)
	}
	fmt.Println("Prime Number:", primeNumber)

	if err != nil {
		log.Fatalf("Error parsing PRIME_NUMBER: %v", err)
	}

	privateKey, _ := rand.Int(rand.Reader, p)
	publicKey := new(big.Int).Exp(g, privateKey, p)

	conn, err := net.Dial("tcp", os.Getenv("SERVER_ADDRESS"))
	if err != nil {
		panic(err)
	}

	// defer conn.Close()

	fmt.Println("Sending Public Key:", publicKey)
	fmt.Fprintf(conn, "%s\n", publicKey.String())

	var serverPublicKeyStr string
	fmt.Fscanln(conn, &serverPublicKeyStr)

	serverPublicKey := new(big.Int)
	serverPublicKey.SetString(serverPublicKeyStr, 10)

	sharedSecret := new(big.Int).Exp(serverPublicKey, privateKey, p)
	fmt.Println("Shared Secret:", sharedSecret)

	key := deriveKey(sharedSecret.Bytes())

	for _, str := range strings {
		encrypted := encryptMessage([]byte(str), key)
		conn.Write(append(encrypted, '\n'))
		fmt.Println("Sent Encrypted Message:", string(encrypted))
	}
	conn.Close()
}

func deriveKey(secret []byte) []byte {
	hkdf := hkdf.New(sha256.New, secret, nil, nil)
	key := make([]byte, 32)
	io.ReadFull(hkdf, key)
	return key
}

func encryptMessage(message, key []byte) []byte {
	encrypted := make([]byte, len(message))
	for i := range message {
		encrypted[i] = message[i] ^ key[i%len(key)]
	}
	return encrypted
}
