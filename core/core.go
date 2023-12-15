package core

import (
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/scrypt"
)

type mode int

const (
	encryption mode = iota
	decryption
)

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024
)

//go:embed wordlist.txt
var embedded embed.FS

type processor struct {
	c          *chacha20.Cipher
	blake      hash.Hash
	source     *os.File
	nonce      []byte
	blakeSalt  []byte
	sourceSize int64
}

// Creates new ChaCha20-Blake2b processor with underlying "source" file.
func newProcessor(sourcePath string, password string, mode mode) (*processor, error) {
	file, err := os.Open(sourcePath)
	if err != nil {
		file.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("file not found")
		}
		return nil, err
	}
	fileInfo, err := os.Stat(sourcePath)
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
	if mode == encryption {
		n, err = io.ReadFull(rand.Reader, nonce)
	} else {
		n, err = io.ReadFull(file, nonce)
	}
	if n != chacha20.NonceSize {
		file.Close()
		return nil, fmt.Errorf("error generating/reading nonce; %v", err)
	}

	salt := make([]byte, 16)
	if mode == encryption {
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

func (p *processor) updateMac(data []byte) error {
	n, err := p.blake.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("could not write all bytes to mac")
	}
	return nil
}

// Derives a key using scrypt KDF.
func deriveKey(password string, salt []byte) ([]byte, error) {
	defer debug.FreeOSMemory() // Free memory held after scrypt call
	if len(salt) != 16 {
		return nil, errors.New("wrong scrypt salt length")
	}
	return scrypt.Key([]byte(password), salt, 65536, 8, 1, 32) // 65536 == 2^16
}

// Checks whenever given slice of strings contains duplicates.
func hasDuplicates(s []string) bool {
	a := make(map[string]bool)
	for _, v := range s {
		if _, e := a[v]; !e {
			a[v] = true
		} else {
			return true
		}
	}
	return false
}

// Checks whenever given slice of paths contains duplicate filenames.
func hasDuplicateFilenames(s []string) bool {
	a := make(map[string]bool)
	for _, v := range s {
		if _, e := a[filepath.Base(v)]; !e {
			a[filepath.Base(v)] = true
		} else {
			return true
		}
	}
	return false
}

func closeAndRemove(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}

func filenameOverflow(s string, n int) string {
	r := []rune(s)
	if len(r) < n {
		return s
	}
	return string(r[:n]) + "..."
}

func formatSize(b int64) string {
	switch {
	case b >= GiB:
		return fmt.Sprintf("(%.02f GiB)", float64(b)/GiB)
	case b >= MiB:
		return fmt.Sprintf("(%.02f MiB)", float64(b)/MiB)
	case b >= KiB:
		return fmt.Sprintf("(%.02f KiB)", float64(b)/KiB)
	default:
		return fmt.Sprintf("(%d B)", b)
	}
}

// Creates new progress bar pool.
func newBarPool(paths []string, noEmoji bool) (pool *pb.Pool, bars []*pb.ProgressBar) {
	barTmpl := `{{ string . "status" }} {{ string . "filename" }} {{ string . "filesize" }} {{ bar . "[" "-"  ">" " " "]" }} {{ string . "error" }}`
	for _, path := range paths {
		bar := pb.New64(1).SetTemplateString(barTmpl).SetWidth(90)
		bar.Set("status", ConditionalPrefix("  ", "", noEmoji))
		bar.Set("filename", filenameOverflow(filepath.Base(path), 25))
		bars = append(bars, bar)
	}
	return pb.NewPool(bars...), bars
}

func barFail(bar *pb.ProgressBar, err error, noEmoji bool) {
	bar.Set("status", ConditionalPrefix("❌", "", noEmoji))
	bar.Set("error", err)
}

// Generates a secure passphrase of a given length.
// Returns error if length < 6.
// The resulting passphrase has it's words joined with "-" in between them.
func GeneratePassphrase(length int) (string, error) {
	if length < 6 {
		return "", errors.New("length less than 6 is not secure")
	}
	wordlist, err := embedded.ReadFile("wordlist.txt")
	if err != nil {
		return "", err
	}
	words := strings.Split(string(wordlist), "\n")

	var passhprase []string
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", err
		}
		passhprase = append(passhprase, words[n.Int64()])
	}
	return strings.Join(passhprase, "-"), nil
}

// Cleans given paths and ouputDir and checks for duplicates.
// Also checks for duplicate filenames if outputDir is not empty.
// Returns cleaned paths or error if any of the checks failed.
func CleanAndCheckPaths(paths []string, outputDir string) ([]string, string, error) {
	if len(paths) == 1 && paths[0] == "" {
		return nil, "", errors.New("empty path sequence")
	}

	for i := 0; i < len(paths); i++ {
		paths[i] = filepath.Clean(paths[i])
	}

	if hasDuplicates(paths) {
		return nil, "", errors.New("duplicate paths are not allowed")
	}

	if outputDir != "" {
		outputDir = filepath.Clean(outputDir)
		fileInfo, err := os.Stat(outputDir)
		if err != nil {
			return nil, "", err
		}
		if !fileInfo.IsDir() {
			return nil, "", fmt.Errorf("'%s' is not a directory", filepath.Base(outputDir))
		}

		if hasDuplicateFilenames(paths) {
			return nil, "", errors.New("duplicate filenames are not allowed with output (-o) flag")
		}
	}

	return paths, outputDir, nil
}

func ConditionalPrefix(prefix string, s string, withoutPrefix bool) string {
	if withoutPrefix {
		return s
	}
	return prefix + s
}
