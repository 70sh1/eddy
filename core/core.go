package core

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"runtime/debug"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/scrypt"
)

type Mode int

const (
	Encryption Mode = iota
	Decryption
)

const (
	headerLen = 92
	bufSize   = 2048 * 2048
)

//go:embed wordlist.txt
var wordlist string

type processor struct {
	c          *chacha20.Cipher
	blake      hash.Hash
	source     *os.File
	nonce      []byte
	scryptSalt []byte
}

// Creates new ChaCha20-BLAKE2b processor with underlying "source" file.
func newProcessor(source *os.File, password string, mode Mode) (*processor, error) {
	nonce := make([]byte, chacha20.NonceSize)
	var err error
	if mode == Encryption {
		_, err = io.ReadFull(rand.Reader, nonce)
	} else {
		_, err = io.ReadFull(source, nonce)
	}
	if err != nil {
		return nil, fmt.Errorf("error generating/reading nonce: %w", err)
	}

	salt := make([]byte, 16)
	if mode == Encryption {
		_, err = io.ReadFull(rand.Reader, salt)
	} else {
		_, err = io.ReadFull(source, salt)
	}
	if err != nil {
		return nil, fmt.Errorf("error generating/reading salt: %w", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("error initializing cipher: %w", err)
	}

	blakeKey := make([]byte, 64)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	if err != nil {
		return nil, err
	}

	return &processor{c, blake, source, nonce, salt}, nil
}

// Derives a key using scrypt KDF.
func deriveKey(password string, salt []byte) ([]byte, error) {
	defer debug.FreeOSMemory() // Free memory held after scrypt call
	if len(salt) != 16 {
		return nil, errors.New("wrong scrypt salt length")
	}
	return scrypt.Key([]byte(password), salt, 65536, 8, 1, 32) // 65536 == 2^16
}

// Generates a secure passphrase of a given length.
// Returns error if length < 6.
// The resulting passphrase has it's words joined with "-" in between them.
func GeneratePassphrase(length int) (string, error) {
	if length < 6 {
		return "", errors.New("length less than 6 is not secure")
	}
	words := strings.Split(wordlist, "\n")

	passhprase := make([]string, 0, length)
	for range length {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", err
		}
		passhprase = append(passhprase, words[n.Int64()])
	}
	return strings.Join(passhprase, "-"), nil
}
