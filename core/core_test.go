package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/70sh1/eddy/testutils"
	"github.com/cheggaaa/pb/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const password = "super-secret"

func TestGeneratePassphrase(t *testing.T) {
	cases := []int{6, 7, 8, 9, 10, 12, 15, 50}
	var results []string
	for _, tCase := range cases {
		for i := 0; i <= 10; i++ {
			result, err := GeneratePassphrase(tCase)

			require.NoError(t, err)
			require.NotContains(t, results, result)
			results = append(results, result)

			slicedResult := strings.Split(result, "-")
			require.Len(t, slicedResult, tCase)
		}
	}
}

func TestGeneratePassphraseError(t *testing.T) {
	for i := -5; i < 6; i++ {
		result, err := GeneratePassphrase(i)
		require.Error(t, err)
		require.Empty(t, result)
	}
}

func TestDeriveKey(t *testing.T) {
	salt := make([]byte, 16)
	expected := []byte{109, 66, 50, 205, 63, 130, 146, 138, 189, 10, 154, 105, 97, 19, 148, 109, 214, 241, 66, 12, 148, 111, 191, 27, 81, 75, 32, 4, 123, 156, 194, 166}

	key, err := deriveKey(password, salt)
	require.NoError(t, err)
	require.Equal(t, expected, key)
}

func TestDeriveKeyError(t *testing.T) {
	var cases [][]byte
	for i := 0; i < 16; i++ {
		cases = append(cases, make([]byte, i))
	}
	for i := 17; i <= 256; i++ {
		cases = append(cases, make([]byte, i))
	}
	for _, tCase := range cases {
		key, err := deriveKey(password, tCase)
		require.Error(t, err)
		require.Nil(t, key)
	}
}

func TestNewProcessor(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	files := []string{filepath.Join(dir, "big.txt"), filepath.Join(dir, "small.txt")}
	fileSizes := []int64{10_485_760, 24}

	for i := 0; i < len(files); i++ {
		processor, err := newProcessor(files[i], password, Encryption)
		require.NoError(t, err)
		processor.source.Close()
		require.NotNil(t, processor.c)
		require.NotNil(t, processor.source)
		require.Equal(t, fileSizes[i], processor.sourceSize)
		require.Len(t, processor.nonce, chacha20.NonceSize)
		require.Len(t, processor.scryptSalt, 16)
	}

	processor, err := newProcessor(filepath.Join(dir, "small.txt.eddy"), password, Decryption)
	require.NoError(t, err)
	processor.source.Close()
	require.NotNil(t, processor.c)
	require.NotNil(t, processor.source)
	require.Equal(t, int64(116), processor.sourceSize)
	require.Equal(t, []byte{159, 21, 91, 197, 188, 218, 176, 90, 10, 110, 138, 23}, processor.nonce)
	require.Equal(t, []byte{39, 152, 144, 26, 35, 122, 186, 87, 36, 248, 3, 230, 164, 17, 138, 182}, processor.scryptSalt)
}

func TestNewProcessorError(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	modes := []Mode{Encryption, Decryption}

	for _, mode := range modes {
		processor, err := newProcessor(filepath.Join(dir, "this-doesnt-exist"), password, mode)
		require.EqualError(t, err, "file not found")
		require.Nil(t, processor)
	}

	for _, mode := range modes {
		processor, err := newProcessor(filepath.Join(dir, "dir1"), password, mode)
		require.EqualError(t, err, "processing directories is not supported")
		require.Nil(t, processor)
	}

	processor, err := newProcessor(filepath.Join(dir, "empty.txt"), password, Decryption)
	require.ErrorContains(t, err, "error generating/reading nonce")
	require.Nil(t, processor)

	processor, err = newProcessor(filepath.Join(dir, "too-short.txt.eddy"), password, Decryption)
	require.ErrorContains(t, err, "error generating/reading salt")
	require.Nil(t, processor)
}

func TestEncryptorRead(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	source, err := os.Open(filepath.Join(dir, "big.txt"))
	if err != nil {
		source.Close()
		panic(err)
	}
	defer source.Close()
	nonce := make([]byte, chacha20.NonceSize)
	salt := make([]byte, 16)
	key, err := deriveKey(password, salt)
	testutils.PanicIfErr(err)
	blakeKey := make([]byte, 32)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	testutils.PanicIfErr(err)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	testutils.PanicIfErr(err)
	encryptor := &encryptor{&processor{c, blake, source, nonce, salt, 10_485_760}}
	buf := make([]byte, 128)
	expectedBuf := []byte{1, 162, 190, 84, 106, 208, 57, 159, 172, 57, 227, 136, 60, 166, 145, 17, 0, 194, 255, 76, 197, 228, 129, 157, 209, 248, 40, 93, 149, 211, 221, 109, 251, 214, 18, 213, 230, 42, 48, 214, 28, 60, 84, 169, 94, 135, 212, 110, 216, 143, 78, 168, 171, 60, 206, 127, 138, 131, 57, 79, 169, 166, 157, 219, 115, 171, 115, 19, 100, 249, 149, 39, 99, 164, 190, 150, 102, 46, 156, 23, 148, 112, 204, 102, 2, 56, 27, 250, 128, 7, 62, 172, 130, 233, 89, 76, 59, 55, 12, 241, 49, 134, 10, 182, 246, 217, 80, 208, 15, 188, 111, 110, 133, 243, 36, 243, 154, 146, 82, 187, 233, 225, 64, 212, 185, 168, 78, 20}

	n, err := encryptor.Read(buf)

	require.NoError(t, err)
	require.Equal(t, 128, n)
	require.Equal(t, expectedBuf, buf)
}

func TestEncryptorReadEOF(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	source, err := os.Open(filepath.Join(dir, "empty.txt"))
	if err != nil {
		source.Close()
		panic(err)
	}
	defer source.Close()
	nonce := make([]byte, chacha20.NonceSize)
	salt := make([]byte, 16)
	key, err := deriveKey(password, salt)
	testutils.PanicIfErr(err)
	blakeKey := make([]byte, 32)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	testutils.PanicIfErr(err)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	testutils.PanicIfErr(err)

	encryptor := &encryptor{&processor{c, blake, source, nonce, salt, 0}}
	buf := make([]byte, 128)

	n, err := encryptor.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, n, 0)
	require.Equal(t, buf, make([]byte, 128))
}

func TestDecryptorRead(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	source := filepath.Join(dir, "small.txt.eddy")
	processor, err := newProcessor(source, password, Decryption)
	testutils.PanicIfErr(err)
	defer processor.source.Close()
	decryptor := &decryptor{processor}
	decryptor.source.Read(make([]byte, 64)) // Skip tag
	buf := make([]byte, 128)
	expectedBuf := []byte("Hello, world.\nSome text!")

	n, err := decryptor.Read(buf)
	buf = buf[:n]

	require.NoError(t, err)
	require.Equal(t, 24, n)
	require.Equal(t, expectedBuf, buf)
}

func TestDecryptorReadEOF(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	source := filepath.Join(dir, "header-only.txt.eddy")
	processor, err := newProcessor(source, password, Decryption)
	testutils.PanicIfErr(err)

	defer processor.source.Close()
	decryptor := &decryptor{processor}
	decryptor.source.Read(make([]byte, 64)) // Skip tag
	buf := make([]byte, 128)

	n, err := decryptor.Read(buf)

	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, n, 0)
	require.Equal(t, buf, make([]byte, 128))
}

func TestEncryptDecryptFile(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	inputs := []string{filepath.Join(dir, "small.txt"), filepath.Join(dir, "big.txt")}
	expectedFileSizes := []int64{116, 10_485_852}

	for i := 0; i < len(inputs); i++ {
		input := inputs[i]
		output := input + ".eddy"
		inputFileContent, err := os.ReadFile(input)
		testutils.PanicIfErr(err)
		bar := &pb.ProgressBar{}
		err = EncryptFile(input, output, password, bar)
		require.NoError(t, err)
		require.FileExists(t, output)
		outputFileContent, err := os.ReadFile(output)
		testutils.PanicIfErr(err)
		require.Equal(t, expectedFileSizes[i], int64(len(outputFileContent)))
		require.NotEqual(t, inputFileContent, outputFileContent[headerLen:])
	}

	testDecryptFile(t, dir)
}

func testDecryptFile(t *testing.T, dir string) {
	err := os.Remove(filepath.Join(dir, "small.txt"))
	testutils.PanicIfErr(err)
	err = os.Remove(filepath.Join(dir, "big.txt"))
	testutils.PanicIfErr(err)

	inputs := []string{filepath.Join(dir, "small.txt.eddy"), filepath.Join(dir, "big.txt.eddy")}
	expectedOutputContent := [][]byte{[]byte("Hello, world.\nSome text!"), make([]byte, 10_485_760)}

	for i := 0; i < len(inputs); i++ {
		input := inputs[i]
		output := strings.TrimSuffix(input, ".eddy")
		inputFileContent, err := os.ReadFile(input)
		testutils.PanicIfErr(err)
		bar := &pb.ProgressBar{}
		err = DecryptFile(input, output, password, bar)
		require.NoError(t, err)
		require.FileExists(t, output)
		outputFileContent, err := os.ReadFile(output)
		testutils.PanicIfErr(err)

		require.Equal(t, expectedOutputContent[i], outputFileContent)
		require.NotEqual(t, inputFileContent, outputFileContent)
	}
}

func TestDecryptFileError(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

	err := os.Remove(filepath.Join(dir, "small.txt"))
	testutils.PanicIfErr(err)

	input := filepath.Join(dir, "small.txt.eddy")
	output := strings.TrimSuffix(input, ".eddy")
	err = DecryptFile(input, output, "wrong-password", &pb.ProgressBar{})
	require.Error(t, err)
	require.NoFileExists(t, output)
}
