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

const headerLen = 92

//go:embed wordlist.txt
var wordlist string

type processor struct {
	c          *chacha20.Cipher
	blake      hash.Hash
	source     *os.File
	nonce      []byte
	scryptSalt []byte
	sourceSize int64
}

// Creates new ChaCha20-BLAKE2b processor with underlying "source" file.
func newProcessor(sourcePath string, password string, mode Mode) (*processor, error) {
	file, err := os.Open(sourcePath)
	if err != nil {
		file.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("file not found")
		}
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if fileInfo.IsDir() {
		file.Close()
		return nil, errors.New("processing directories is not supported")
	}
	fileSize := fileInfo.Size()

	nonce := make([]byte, chacha20.NonceSize)
	var n int
	if mode == Encryption {
		n, err = io.ReadFull(rand.Reader, nonce)
	} else {
		n, err = io.ReadFull(file, nonce)
	}
	if n != chacha20.NonceSize {
		file.Close()
		return nil, fmt.Errorf("error generating/reading nonce; %v", err)
	}

	salt := make([]byte, 16)
	if mode == Encryption {
		n, err = io.ReadFull(rand.Reader, salt)
	} else {
		n, err = io.ReadFull(file, salt)
	}
	if n != 16 {
		file.Close()
		return nil, fmt.Errorf("error generating/reading salt; %v", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		file.Close()
		return nil, err
	}

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("error initializing cipher; %v", err)
	}

	blakeKey := make([]byte, 64)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &processor{c, blake, file, nonce, salt, fileSize}, nil
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
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", err
		}
		passhprase = append(passhprase, words[n.Int64()])
	}
	return strings.Join(passhprase, "-"), nil
}
