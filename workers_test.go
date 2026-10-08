package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestRunFileWorkersConcurrency(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		limit int
	}{
		{"empty batch", 0, 4},
		{"small batch", 1, 4},
		{"serial", 5, 1},
		{"parallel", 7, 2},
		{"above 51 workers", 67, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := runtime.GOMAXPROCS(tc.limit)
			defer runtime.GOMAXPROCS(previous)
			synctest.Test(t, func(t *testing.T) {
				started := make(chan int, tc.count)
				release := make(chan struct{})
				done := make(chan struct{})
				completed := make([]int, tc.count)
				released := false
				defer func() {
					if !released {
						close(release)
					}
				}()
				go func() {
					runFileWorkers(tc.count, func(i int) {
						started <- i
						<-release
						completed[i]++
					})
					close(done)
				}()

				// Wait until every goroutine is blocked. This checks the actual
				// number of active callbacks without timing or sleep assumptions.
				synctest.Wait()
				require.Len(t, started, min(tc.count, tc.limit))
				close(release)
				released = true
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("batch did not finish")
				}
				require.Len(t, started, tc.count)
				for i, times := range completed {
					require.Equal(t, 1, times, "file %d must run exactly once", i)
				}
			})
		})
	}
}

func TestBatchesContinueAfterWorkerFailures(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	missing := filepath.Join(dir, "missing")
	encrypted := input + ".eddy"
	plaintext := []byte("files after a failed worker must still be processed")
	require.NoError(t, os.WriteFile(input, plaintext, 0o600))

	err := encryptFiles([]string{missing, input}, []string{missing + ".eddy", encrypted}, "password", false, true)
	require.ErrorContains(t, err, "file not found")
	require.FileExists(t, encrypted)
	require.NoFileExists(t, missing+".eddy")

	corrupt := filepath.Join(dir, "corrupt.eddy")
	ciphertext, err := os.ReadFile(encrypted)
	require.NoError(t, err)
	ciphertext[28] ^= 1 // Corrupt the MAC to exercise a failure after processing.
	require.NoError(t, os.WriteFile(corrupt, ciphertext, 0o600))
	outputs := []string{filepath.Join(dir, "missing-output"), filepath.Join(dir, "corrupt-output"), filepath.Join(dir, "decrypted")}
	err = decryptFiles([]string{missing, corrupt, encrypted}, outputs, "password", false, false, true)
	require.ErrorContains(t, err, "file not found")
	require.ErrorContains(t, err, "incorrect password or corrupt/forged data")
	for _, output := range outputs[:2] {
		require.NoFileExists(t, output)
	}
	actual, err := os.ReadFile(outputs[2])
	require.NoError(t, err)
	require.Equal(t, plaintext, actual)
	temporary, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	require.NoError(t, err)
	require.Empty(t, temporary)
}
