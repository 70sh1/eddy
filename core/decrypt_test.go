package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/70sh1/eddy/pathutils"
	"github.com/70sh1/eddy/testutils"
	"github.com/stretchr/testify/require"
)

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestDecryptFileAuthenticatesConsumedCiphertext(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	ciphertext, err := os.ReadFile(filepath.Join(dir, "small.txt.eddy"))
	require.NoError(t, err)
	input := filepath.Join(t.TempDir(), "input.eddy")
	require.NoError(t, os.WriteFile(input, ciphertext, 0o600))
	source, err := os.OpenFile(input, os.O_RDWR, 0)
	require.NoError(t, err)
	defer source.Close()
	output := filepath.Join(filepath.Dir(input), "output")
	changed := false
	progress := writerFunc(func(b []byte) (int, error) {
		if !changed {
			// Change a byte after it has been consumed by the MAC. It must
			// never be read again and used to produce unauthenticated output.
			_, err := source.WriteAt([]byte{ciphertext[headerLen] ^ 1}, headerLen)
			require.NoError(t, err)
			changed = true
		}
		return len(b), nil
	})

	require.NoError(t, DecryptFile(source, output, password, false, progress))
	require.True(t, changed)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("Hello, world.\nSome text!"), actual)
}

func TestDecryptFileRejectsChangesToUnreadCiphertext(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	plaintext := bytes.Repeat([]byte{0xa5}, bufSize+32)
	require.NoError(t, os.WriteFile(input, plaintext, 0o600))
	source, err := os.Open(input)
	require.NoError(t, err)
	encrypted := input + ".eddy"
	require.NoError(t, EncryptFile(source, encrypted, password, io.Discard))
	require.NoError(t, source.Close())
	source, err = os.OpenFile(encrypted, os.O_RDWR, 0)
	require.NoError(t, err)
	defer source.Close()
	output := filepath.Join(dir, "output")
	previous := []byte("existing output")
	require.NoError(t, os.WriteFile(output, previous, 0o600))
	changed := false
	progress := writerFunc(func(b []byte) (int, error) {
		if !changed {
			offset, err := source.Seek(0, io.SeekCurrent)
			require.NoError(t, err)
			one := make([]byte, 1)
			_, err = source.ReadAt(one, offset)
			require.NoError(t, err)
			one[0] ^= 1
			_, err = source.WriteAt(one, offset)
			require.NoError(t, err)
			changed = true
		}
		return len(b), nil
	})

	err = DecryptFile(source, output, password, false, progress)
	require.ErrorContains(t, err, "incorrect password or corrupt/forged data")
	require.True(t, changed)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, previous, actual)
	temporary, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	require.NoError(t, err)
	require.Empty(t, temporary)
}

func TestDecryptFileProcessesPayloadOnce(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	for _, name := range []string{"small.txt.eddy", "header-only.txt.eddy"} {
		t.Run(name, func(t *testing.T) {
			source, size, err := pathutils.OpenAndGetSize(filepath.Join(dir, name))
			require.NoError(t, err)
			defer source.Close()
			var processed int64
			progress := writerFunc(func(b []byte) (int, error) {
				processed += int64(len(b))
				return len(b), nil
			})
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, DecryptFile(source, output, password, false, progress))
			require.Equal(t, size-headerLen, processed)
		})
	}
}

func TestDecryptFileRejectsInvalidData(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	original, err := os.ReadFile(filepath.Join(dir, "small.txt.eddy"))
	require.NoError(t, err)
	cases := []struct {
		name   string
		modify func([]byte) []byte
		key    string
	}{
		{"wrong password", func(b []byte) []byte { return b }, "wrong-password"},
		{"nonce", func(b []byte) []byte { b[0] ^= 1; return b }, password},
		{"salt", func(b []byte) []byte { b[12] ^= 1; return b }, password},
		{"tag", func(b []byte) []byte { b[28] ^= 1; return b }, password},
		{"ciphertext", func(b []byte) []byte { b[headerLen] ^= 1; return b }, password},
		{"truncated payload", func(b []byte) []byte { return b[:len(b)-1] }, password},
		{"appended payload", func(b []byte) []byte { return append(b, 0) }, password},
		{"short tag", func(b []byte) []byte { return b[:headerLen-1] }, password},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.eddy")
			require.NoError(t, os.WriteFile(input, tc.modify(bytes.Clone(original)), 0o600))
			source, err := os.Open(input)
			require.NoError(t, err)
			defer source.Close()
			output := filepath.Join(dir, "output")
			previous := []byte("existing output")
			require.NoError(t, os.WriteFile(output, previous, 0o600))

			require.Error(t, DecryptFile(source, output, tc.key, false, io.Discard))
			actual, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, previous, actual)
			temporary, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
			require.NoError(t, err)
			require.Empty(t, temporary)
		})
	}
}

func TestDecryptFileForceBypassesAuthentication(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	input := filepath.Join(dir, "small.txt.eddy")
	ciphertext, err := os.ReadFile(input)
	require.NoError(t, err)
	ciphertext[28] ^= 1
	require.NoError(t, os.WriteFile(input, ciphertext, 0o600))
	for _, key := range []string{password, "wrong-password"} {
		t.Run(key, func(t *testing.T) {
			source, err := os.Open(input)
			require.NoError(t, err)
			defer source.Close()
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, DecryptFile(source, output, key, true, io.Discard))
			actual, err := os.ReadFile(output)
			require.NoError(t, err)
			if key == password {
				require.Equal(t, []byte("Hello, world.\nSome text!"), actual)
			} else {
				require.NotEqual(t, []byte("Hello, world.\nSome text!"), actual)
			}
		})
	}
}

func TestDecryptFileProgressFailurePreservesOutput(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	source, err := os.Open(filepath.Join(dir, "small.txt.eddy"))
	require.NoError(t, err)
	defer source.Close()
	outputDir := t.TempDir()
	output := filepath.Join(outputDir, "output")
	previous := []byte("existing output")
	require.NoError(t, os.WriteFile(output, previous, 0o600))
	failure := errors.New("progress failed")
	progress := writerFunc(func(b []byte) (int, error) { return 0, failure })

	require.ErrorIs(t, DecryptFile(source, output, password, false, progress), failure)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, previous, actual)
	entries, err := os.ReadDir(outputDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func BenchmarkDecryptFile(b *testing.B) {
	const size = 64 * 1024 * 1024
	dir := b.TempDir()
	input, err := os.Create(filepath.Join(dir, "input"))
	require.NoError(b, err)
	require.NoError(b, input.Truncate(size))
	encrypted := filepath.Join(dir, "input.eddy")
	require.NoError(b, EncryptFile(input, encrypted, password, io.Discard))
	require.NoError(b, input.Close())
	source, err := os.Open(encrypted)
	require.NoError(b, err)
	defer source.Close()
	output := filepath.Join(dir, "output")
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := source.Seek(0, io.SeekStart)
		require.NoError(b, err)
		require.NoError(b, DecryptFile(source, output, password, false, io.Discard))
	}
}
