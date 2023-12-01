package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cheggaaa/pb/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const password = "super-secret"

func testFilesSetup() string {
	tmpDir, err := os.MkdirTemp(".", "test-tmp-*")
	panicIfErr(err)

	if err := os.Mkdir(filepath.Join(tmpDir, "dir1"), 0700); err != nil {
		panic(err)
	}

	f1, err := os.Create(filepath.Join(tmpDir, "small.txt"))
	panicIfErr(err)
	defer f1.Close()
	if _, err := f1.Write([]byte("Hello, world.\nSome text!")); err != nil {
		panic(err)
	}

	f2, err := os.Create(filepath.Join(tmpDir, "big.txt"))
	panicIfErr(err)
	defer f2.Close()
	if _, err := f2.Write(make([]byte, 10_485_760)); err != nil {
		panic(err)
	}

	f3, err := os.Create(filepath.Join(tmpDir, "empty.txt"))
	panicIfErr(err)
	defer f3.Close()

	f5, err := os.Create(filepath.Join(tmpDir, "too-short.txt.eddy"))
	panicIfErr(err)
	defer f5.Close()
	if _, err := f5.Write(make([]byte, 20)); err != nil {
		panic(err)
	}

	f6, err := os.Create(filepath.Join(tmpDir, "small.txt.eddy"))
	panicIfErr(err)
	defer f6.Close()
	data := []byte{159, 21, 91, 197, 188, 218, 176, 90, 10, 110, 138, 23, 39, 152, 144, 26, 35, 122, 186, 87, 36, 248, 3, 230, 164, 17, 138, 182, 113, 220, 194, 163, 53, 58, 163, 57, 201, 213, 196, 205, 79, 204, 10, 223, 235, 18, 113, 176, 69, 50, 177, 184, 154, 71, 214, 152, 59, 120, 122, 110, 205, 213, 245, 240, 27, 106, 22, 68, 86, 125, 206, 108, 28, 82, 100, 17, 12, 30, 199, 215, 6, 60, 216, 244, 44, 84, 142, 118, 109, 63, 20, 96, 171, 160, 226, 33, 68, 13, 87, 200, 177, 239, 108, 135, 126, 146, 48, 141, 93, 23, 92, 63, 199, 216, 38, 167}
	if _, err := f6.Write(data); err != nil {
		panic(err)
	}

	f7, err := os.Create(filepath.Join(tmpDir, "header-only.txt.eddy"))
	panicIfErr(err)
	defer f7.Close()
	if _, err := f7.Write(make([]byte, 92)); err != nil {
		panic(err)
	}
	return tmpDir
}

func testFilesCleanup(tmpDir string) {
	defer os.RemoveAll(tmpDir)

}
func TestHasDuplicates(t *testing.T) {
	cases := []struct {
		in       []string
		expected bool
	}{
		{
			in:       []string{"a", "b", "a"},
			expected: true,
		},
		{
			in:       []string{"a", "a", "a"},
			expected: true,
		},
		{
			in:       []string{"a", "b", "c"},
			expected: false,
		},
		{
			in:       []string{"1", "11", "-1"},
			expected: false,
		},
		{
			in:       []string{"a"},
			expected: false,
		},
		{
			in:       []string{""},
			expected: false,
		}}
	for _, tCase := range cases {
		result := hasDuplicates(tCase.in)
		require.Equal(t, tCase.expected, result)
	}
}

func TestHasDuplicateFilenames(t *testing.T) {
	cases := []struct {
		in       []string
		expected bool
	}{
		{
			in:       []string{"C:/test/something.txt", "D:/path/something.txt", "C:/"},
			expected: true,
		},
		{
			in:       []string{"C:/something.txt", "H:/qq", "C:/path/something.txt", "a"},
			expected: true,
		},
		{
			in:       []string{"file1", "file2", "D:/somewhere/file1"},
			expected: true,
		},
		{
			in:       []string{"C:/something.txt", "H:/qq/something", "C:/path/something2.txt"},
			expected: false,
		},
		{
			in:       []string{"a"},
			expected: false,
		},
		{
			in:       []string{""},
			expected: false,
		},
	}
	for _, tCase := range cases {
		result := hasDuplicateFilenames(tCase.in)
		require.Equal(t, tCase.expected, result)
	}
}

func TestFormatSize(t *testing.T) {
	cases := map[int64]string{
		1:            "(1 B)",
		10:           "(10 B)",
		1024:         "(1.00 KiB)",
		2500:         "(2.44 KiB)",
		1048576:      "(1.00 MiB)",
		5398221:      "(5.15 MiB)",
		1073741824:   "(1.00 GiB)",
		120073741824: "(111.83 GiB)",
		-0:           "(0 B)",
		-1:           "(-1 B)",
	}
	for tCase, expected := range cases {
		result := formatSize(tCase)
		require.Equal(t, expected, result)
	}
}

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
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	files := []string{filepath.Join(dir, "big.txt"), filepath.Join(dir, "small.txt")}
	fileSizes := []int64{10_485_760, 24}

	for i := 0; i < len(files); i++ {
		processor, err := NewProcessor(files[i], password, "enc")
		require.NoError(t, err)
		processor.source.Close()
		require.NotNil(t, processor.c)
		require.NotNil(t, processor.source)
		require.Equal(t, fileSizes[i], processor.sourceSize)
		require.Len(t, processor.nonce, chacha20.NonceSize)
		require.Len(t, processor.hmacSalt, 16)
	}

	processor, err := NewProcessor(filepath.Join(dir, "small.txt.eddy"), password, "dec")
	processor.source.Close()
	require.NoError(t, err)
	require.NotNil(t, processor.c)
	require.NotNil(t, processor.source)
	require.Equal(t, int64(116), processor.sourceSize)
	require.Equal(t, []byte{159, 21, 91, 197, 188, 218, 176, 90, 10, 110, 138, 23}, processor.nonce)
	require.Equal(t, []byte{39, 152, 144, 26, 35, 122, 186, 87, 36, 248, 3, 230, 164, 17, 138, 182}, processor.hmacSalt)
}

func TestNewProcessorError(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	modes := []string{"enc", "dec"}

	for _, mode := range modes {
		processor, err := NewProcessor(filepath.Join(dir, "this-doesnt-exist"), password, mode)
		require.EqualError(t, err, "file not found")
		require.Nil(t, processor)
	}

	for _, mode := range modes {
		processor, err := NewProcessor(filepath.Join(dir, "dir1"), password, mode)
		require.EqualError(t, err, "processing directories is not supported")
		require.Nil(t, processor)
	}

	processor, err := NewProcessor(filepath.Join(dir, "empty.txt"), password, "dec")
	require.ErrorContains(t, err, "error generating/reading nonce")
	require.Nil(t, processor)

	processor, err = NewProcessor(filepath.Join(dir, "too-short.txt.eddy"), password, "dec")
	require.ErrorContains(t, err, "error generating/reading salt")
	require.Nil(t, processor)
}

func TestCleanAndCheckPaths(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	cases := []struct {
		pathsIn       []string
		pathsExpected []string
		dirIn         string
		dirExpected   string
	}{
		{
			[]string{"C:/t./11est/something.txt", "D:/path/something.txt", "C:////\\/"},
			[]string{filepath.Clean("C:/t./11est/something.txt"), filepath.Clean("D:/path/something.txt"), filepath.Clean("C:////\\/")},
			"",
			".",
		},
		{
			[]string{"C:\\something.txt", "H:/qq", "a", "/home/\\//user//test/some"},
			[]string{filepath.Clean("C:\\something.txt"), filepath.Clean("H:/qq"), filepath.Clean("a"), filepath.Clean("/home/\\//user//test/some")},
			"",
			".",
		},
		{
			[]string{"file1", "./file2", "/////somewhere\\file3"},
			[]string{filepath.Clean("file1"), filepath.Clean("./file2"), filepath.Clean("/////somewhere\\file3")},
			dir,
			filepath.Clean(dir),
		},
		{
			[]string{"file1"},
			[]string{filepath.Clean("file1")},
			"",
			".",
		},
		{
			[]string{"file.txt"},
			[]string{filepath.Clean("file.txt")},
			dir,
			filepath.Clean(dir),
		},
	}
	for _, tCase := range cases {
		pathsOut, dirOut, err := CleanAndCheckPaths(tCase.pathsIn, tCase.dirIn)
		require.NoError(t, err)
		require.Equal(t, tCase.pathsExpected, pathsOut)
		require.Equal(t, tCase.dirExpected, dirOut)
	}
}

func TestCleanAndCheckPathsError(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	cases := []struct {
		pathsIn        []string
		pathsExpected  []string
		dirIn          string
		dirExpected    string
		errMsgExpected string
	}{
		{
			[]string{""},
			nil,
			"",
			"",
			"empty path sequence",
		},
		{
			[]string{""},
			nil,
			dir,
			"",
			"empty path sequence",
		},
		{
			[]string{"C:\\something.txt", "H:/qq", "a"},
			nil,
			"this-dir-doesnt-exist",
			"",
			"", // Expecting OS specific err
		},
		{
			[]string{"path/to/something", "path\\////to//\\/something/", "file1"},
			nil,
			filepath.Join(dir, "small.txt"),
			"",
			"'small.txt' is not a directory",
		},
		{
			[]string{"path/to/something", "path//to//something/", "file1"},
			nil,
			"",
			"",
			"duplicate paths are not allowed",
		},

		{
			[]string{"usr/path/dir/file", "usr2/another-path/dir2/file"},
			nil,
			dir,
			"",
			"duplicate filenames are not allowed with output (-o) flag",
		},
	}
	for _, tCase := range cases {
		pathsOut, dirOut, err := CleanAndCheckPaths(tCase.pathsIn, tCase.dirIn)
		require.ErrorContains(t, err, tCase.errMsgExpected)
		require.Equal(t, tCase.pathsExpected, pathsOut)
		require.Equal(t, tCase.dirExpected, dirOut)
	}
}

func TestNewBarPool(t *testing.T) {
	cases := [][]string{
		{"file1", "path/file2.dat", "home/user/docs/file2"},
		{"C:/some/dir/file1.txt", "path/file3", "home/user/docs/file2"},
		{"file5"},
	}
	for _, tCase := range cases {
		barPool, bars := newBarPool(tCase)
		require.Len(t, bars, len(tCase))
		require.NotNil(t, barPool)
		for i := 0; i < len(tCase); i++ {
			require.Contains(t, bars[i].String(), filepath.Base(tCase[i]))
		}
	}
}

func TestCloseAndRemove(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	file, err := os.Open(filepath.Join(dir, "small.txt"))
	if err != nil {
		file.Close()
		panic(err)
	}

	closeAndRemove(file)

	require.NoFileExists(t, file.Name())
}
func TestEncryptorRead(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	source, err := os.Open(filepath.Join(dir, "big.txt"))
	if err != nil {
		source.Close()
		panic(err)
	}
	defer source.Close()
	nonce := make([]byte, chacha20.NonceSize)
	salt := make([]byte, 16)
	key, err := deriveKey(password, salt)
	panicIfErr(err)
	blakeKey := make([]byte, 32)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	panicIfErr(err)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	panicIfErr(err)
	encryptor := &encryptor{&processor{c, blake, source, nonce, salt, 10_485_760}}
	buf := make([]byte, 128)
	expectedBuf := []byte{1, 162, 190, 84, 106, 208, 57, 159, 172, 57, 227, 136, 60, 166, 145, 17, 0, 194, 255, 76, 197, 228, 129, 157, 209, 248, 40, 93, 149, 211, 221, 109, 251, 214, 18, 213, 230, 42, 48, 214, 28, 60, 84, 169, 94, 135, 212, 110, 216, 143, 78, 168, 171, 60, 206, 127, 138, 131, 57, 79, 169, 166, 157, 219, 115, 171, 115, 19, 100, 249, 149, 39, 99, 164, 190, 150, 102, 46, 156, 23, 148, 112, 204, 102, 2, 56, 27, 250, 128, 7, 62, 172, 130, 233, 89, 76, 59, 55, 12, 241, 49, 134, 10, 182, 246, 217, 80, 208, 15, 188, 111, 110, 133, 243, 36, 243, 154, 146, 82, 187, 233, 225, 64, 212, 185, 168, 78, 20}

	n, err := encryptor.Read(buf)
	buf = buf[:n]

	require.NoError(t, err)
	require.Equal(t, 128, n)
	require.Equal(t, expectedBuf, buf)
}

func TestEncryptorReadEOF(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	source, err := os.Open(filepath.Join(dir, "empty.txt"))
	if err != nil {
		source.Close()
		panic(err)
	}
	defer source.Close()
	nonce := make([]byte, chacha20.NonceSize)
	salt := make([]byte, 16)
	key, err := deriveKey(password, salt)
	panicIfErr(err)
	blakeKey := make([]byte, 32)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	panicIfErr(err)
	c.XORKeyStream(blakeKey, blakeKey)
	blake, err := blake2b.New512(blakeKey)
	panicIfErr(err)

	encryptor := &encryptor{&processor{c, blake, source, nonce, salt, 0}}
	buf := make([]byte, 128)

	n, err := encryptor.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, n, 0)
	require.Equal(t, buf, make([]byte, 128))
}

func TestDecryptorRead(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	source := filepath.Join(dir, "small.txt.eddy")
	processor, err := NewProcessor(source, password, "dec")
	panicIfErr(err)
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
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	source := filepath.Join(dir, "header-only.txt.eddy")
	processor, err := NewProcessor(source, password, "dec")
	panicIfErr(err)
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
	dir := testFilesSetup()
	defer testFilesCleanup(dir)

	inputs := []string{filepath.Join(dir, "small.txt"), filepath.Join(dir, "big.txt")}
	expectedFileSizes := []int64{116, 10_485_852}

	for i := 0; i < len(inputs); i++ {
		input := inputs[i]
		output := input + ".eddy"
		inputFileContent, err := os.ReadFile(input)
		panicIfErr(err)
		bar := &pb.ProgressBar{}
		err = encryptFile(input, output, password, bar)
		require.NoError(t, err)
		require.FileExists(t, output)
		outputFileContent, err := os.ReadFile(output)
		panicIfErr(err)
		require.Equal(t, expectedFileSizes[i], int64(len(outputFileContent)))
		require.NotEqual(t, inputFileContent, outputFileContent[92:])
	}

	testDecryptFile(t, dir)
}

func testDecryptFile(t *testing.T, dir string) {
	err := os.Remove(filepath.Join(dir, "small.txt"))
	panicIfErr(err)
	err = os.Remove(filepath.Join(dir, "big.txt"))
	panicIfErr(err)

	inputs := []string{filepath.Join(dir, "small.txt.eddy"), filepath.Join(dir, "big.txt.eddy")}
	expectedOutputContent := [][]byte{[]byte("Hello, world.\nSome text!"), make([]byte, 10_485_760)}

	for i := 0; i < len(inputs); i++ {
		input := inputs[i]
		output := strings.TrimSuffix(input, ".eddy")
		inputFileContent, err := os.ReadFile(input)
		panicIfErr(err)
		bar := &pb.ProgressBar{}
		err = decryptFile(input, output, password, bar)
		require.NoError(t, err)
		require.FileExists(t, output)
		outputFileContent, err := os.ReadFile(output)
		panicIfErr(err)

		require.Equal(t, expectedOutputContent[i], outputFileContent)
		require.NotEqual(t, inputFileContent, outputFileContent)
	}
}

func TestDecryptFileError(t *testing.T) {
	dir := testFilesSetup()
	defer testFilesCleanup(dir)
	err := os.Remove(filepath.Join(dir, "small.txt"))
	panicIfErr(err)

	input := filepath.Join(dir, "small.txt.eddy")
	output := strings.TrimSuffix(input, ".eddy")
	err = decryptFile(input, output, "wrong-password", &pb.ProgressBar{})
	require.Error(t, err)
	require.NoFileExists(t, output)

}

func panicIfErr(e error) {
	if e != nil {
		panic(e)
	}
}
