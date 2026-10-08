package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/70sh1/eddy/testutils"
	"github.com/stretchr/testify/require"
)

func TestOutputCreatedDuringProcessing(t *testing.T) {
	fixtures := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(fixtures)
	for _, mode := range []string{"encrypt", "decrypt", "force decrypt"} {
		for _, overwrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/overwrite=%t", mode, overwrite), func(t *testing.T) {
				name := "small.txt"
				if mode != "encrypt" {
					name += ".eddy"
				}
				source, err := os.Open(filepath.Join(fixtures, name))
				require.NoError(t, err)
				defer source.Close()
				dir := t.TempDir()
				output := filepath.Join(dir, "output")
				created := false
				progress := writerFunc(func(b []byte) (int, error) {
					if !created {
						require.NoFileExists(t, output)
						require.NoError(t, os.WriteFile(output, []byte("other process's output"), 0o600))
						created = true
					}
					return len(b), nil
				})
				if mode == "encrypt" {
					err = EncryptFile(source, output, password, overwrite, progress)
				} else {
					err = DecryptFile(source, output, password, mode == "force decrypt", overwrite, progress)
				}
				require.True(t, created)
				actual, readErr := os.ReadFile(output)
				require.NoError(t, readErr)
				if overwrite {
					require.NoError(t, err)
					if mode == "encrypt" {
						require.Len(t, actual, headerLen+len("Hello, world.\nSome text!"))
					} else {
						require.Equal(t, "Hello, world.\nSome text!", string(actual))
					}
				} else {
					require.ErrorIs(t, err, os.ErrExist)
					require.Equal(t, "other process's output", string(actual))
				}
				entries, err := os.ReadDir(dir)
				require.NoError(t, err)
				require.Len(t, entries, 1, "temporary output must be cleaned up")
			})
		}
	}
}
