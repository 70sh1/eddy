package main

import (
	"bytes"
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
	"sync"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/scrypt"
)

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024
)

//go:embed wordlist.txt
var embeded embed.FS

type processor struct {
	c          *chacha20.Cipher
	hmac       hash.Hash
	source     *os.File
	nonce      []byte
	hmacSalt   []byte
	sourceSize int64
}

type encryptor struct {
	*processor
}

type decryptor struct {
	*processor
}

// Create new ChaCha20-Blake2b processor with underlying "source" file.
func NewProcessor(sourcePath string, password string, mode string) (*processor, error) {
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
	if mode == "enc" {
		n, err = rand.Read(nonce)
	} else {
		n, err = file.Read(nonce)
	}
	if n != chacha20.NonceSize {
		file.Close()
		return nil, fmt.Errorf("error generating/reading nonce; %v", err)
	}

	salt := make([]byte, 16)
	if mode == "enc" {
		n, err = rand.Read(salt)
	} else {
		n, err = file.Read(salt)
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
	debug.FreeOSMemory() // Free memory held after scrypt call

	blakeKey := make([]byte, 64)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("error initializing cipher; %v", err)
	}
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &processor{c, blake, file, nonce, salt, fileSize}, nil
}

// Read bytes from encryptor's source (file) into buffer b, truncate it if n < len(b),
// XOR it, update the encryptor's HMAC with the resulting slice,
// return number of bytes read and error.
func (ab *encryptor) Read(b []byte) (int, error) {
	n, err := ab.source.Read(b)
	if n > 0 {
		b = b[:n]
		ab.c.XORKeyStream(b, b)
		if err := ab.updateHmac(b); err != nil {
			return n, err
		}
		return n, err
	}
	return 0, io.EOF
}

// Read bytes from decryptor's source (file) into buffer b, truncate it if n < len(b),
// update HMAC with slice, XOR the slice,
// return number of bytes read and error.
func (ab *decryptor) Read(b []byte) (int, error) {
	n, err := ab.source.Read(b)
	if n > 0 {
		b = b[:n]
		if err := ab.updateHmac(b); err != nil {
			return n, err
		}
		ab.c.XORKeyStream(b, b)
		return n, err
	}
	return 0, io.EOF
}

func (ab *processor) updateHmac(data []byte) error {
	n, err := ab.hmac.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("could not write all bytes to hmac")

	}
	return nil
}

// Check whenever given slice of strings contains duplicates.
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

// Check whenever given slice of paths contains duplicate filenames.
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

func limitStringLength(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
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

func cleanAndCheckPaths(paths []string, outputDir string) ([]string, string, error) {

	if len(paths) == 1 && paths[0] == "" {
		return nil, "", errors.New("empty path sequence")
	}

	// Clean all paths and outputDir
	for i := 0; i < len(paths); i++ {
		paths[i] = filepath.Clean(paths[i])
	}
	outputDir = filepath.Clean(outputDir)

	// Check if outputDir is actually a directory
	fileInfo, err := os.Stat(outputDir)
	if err != nil {
		return nil, "", err
	}
	if !fileInfo.IsDir() {
		return nil, "", fmt.Errorf("'%v' is not a directory", filepath.Base(outputDir))
	}

	if hasDuplicates(paths) {
		return nil, "", errors.New("duplicate paths are not allowed")
	}

	if len(outputDir) > 0 && outputDir != "." {
		if hasDuplicateFilenames(paths) {
			return nil, "", errors.New("duplicate filenames are not allowed with output (-o) flag")
		}
	}

	return paths, outputDir, nil
}

func newBarPool(paths []string) (pool *pb.Pool, bars []*pb.ProgressBar) {
	barTmpl := `{{ string . "status" }} {{ string . "filename" }} {{ string . "filesize" }} {{ bar . "[" "-"  ">" " " "]" }} {{ string . "error" }}`
	for _, path := range paths {
		bar := pb.New64(1).SetTemplateString(barTmpl).SetWidth(80)
		bar.Set("status", "  ")
		bar.Set("filename", limitStringLength(filepath.Base(path), 25))
		bars = append(bars, bar)
	}
	return pb.NewPool(bars...), bars
}

func generatePassphrase(length int) (string, error) {
	if length < 6 {
		return "", errors.New("length < 6 is not secure")
	}
	wordlist, err := embeded.ReadFile("wordlist.txt")
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

func deriveKey(password string, salt []byte) ([]byte, error) {
	if len(salt) != 16 {
		return nil, errors.New("wrong scrypt salt length")
	}
	return scrypt.Key([]byte(password), salt, 65536, 8, 1, 32) // 65536 == 2^16
}

func encryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := NewProcessor(pathIn, password, "enc")
	if err != nil {
		// Moving these repetitive lines to the fucntion call would be nice and much cleaner,
		// but then the bar doesn't update properly for some reason.
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}
	encryptor := &encryptor{processor}
	defer encryptor.source.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}
	defer closeAndRemove(tmpFile)

	var header []byte
	tagPlaceholder := make([]byte, encryptor.hmac.Size())
	header = append(header, encryptor.nonce...)
	header = append(header, encryptor.hmacSalt...)
	header = append(header, tagPlaceholder...)

	if _, err := tmpFile.Write(header); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	bar.Set("filesize", formatSize(encryptor.sourceSize))
	bar.SetTotal(encryptor.sourceSize)
	w := bar.NewProxyWriter(tmpFile)
	defer w.Close()

	if _, err := io.Copy(w, encryptor); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	tag := encryptor.hmac.Sum(nil)
	if _, err := tmpFile.Seek(int64(len(encryptor.nonce)+len(encryptor.hmacSalt)), 0); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}
	if _, err := tmpFile.Write(tag); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	tmpFile.Close()
	encryptor.source.Close()
	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	bar.SetCurrent(bar.Total())
	bar.Set("status", "🔒")
	return nil
}

func decryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := NewProcessor(pathIn, password, "dec")
	if err != nil {
		bar.Set("status", "❌")
		bar.Set("error", errors.Unwrap(err))
		return err
	}
	decryptor := &decryptor{processor}
	defer decryptor.source.Close()

	expectedTag := make([]byte, 64)
	n, err := decryptor.source.Read(expectedTag)
	if n != 64 || err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}
	defer closeAndRemove(tmpFile)

	bar.Set("filesize", formatSize(decryptor.sourceSize))
	bar.SetTotal(decryptor.sourceSize)
	w := bar.NewProxyWriter(tmpFile)
	defer w.Close()

	if _, err := io.Copy(w, decryptor); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	tmpFile.Close()
	decryptor.source.Close()

	actualTag := decryptor.hmac.Sum(nil)
	if !bytes.Equal(actualTag, expectedTag) {
		err = errors.New("incorrect password or corrupt/forged data")
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		bar.Set("status", "❌")
		bar.Set("error", err)
		return err
	}

	bar.SetCurrent(bar.Total())
	bar.Set("status", "🔓")
	return nil
}

func encryptFiles(paths []string, outputDir, password string, overwrite bool) (int64, error) {
	var wg sync.WaitGroup
	var numProcessed int64

	barPool, bars := newBarPool(paths)
	if err := barPool.Start(); err != nil {
		return 0, err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := bars[i]
		fileIn := paths[i]
		go func() {
			defer wg.Done()
			fileOut := fileIn + ".eddy"
			if len(outputDir) > 0 {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				bar.Set("status", "❌")
				bar.Set("error", "output already exists")
				return
			}
			if err := encryptFile(fileIn, fileOut, password, bar); err != nil {
				return
			}
			numProcessed += 1
		}()
	}

	wg.Wait()
	barPool.Stop()
	return numProcessed, nil
}

func decryptFiles(paths []string, outputDir, password string, overwrite bool) error {
	var wg sync.WaitGroup

	barPool, bars := newBarPool(paths)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		fileIn := paths[i]
		bar := bars[i]
		go func() {
			defer wg.Done()
			fileOut := strings.TrimSuffix(fileIn, ".eddy")
			if len(outputDir) > 0 {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				bar.Set("status", "❌")
				bar.Set("error", "output already exists")
				return
			}
			decryptFile(fileIn, fileOut, password, bar)
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
