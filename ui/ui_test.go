package ui

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmoji(t *testing.T) {
	require.Equal(t, "🔑 ", Emoji("🔑 ", false))
	require.Empty(t, Emoji("🔑 ", true))
}

func TestNewBarPool(t *testing.T) {
	cases := [][]string{
		{"file1", "path/file2.dat", "home/user/docs/file2"},
		{"C:/some/dir/file1.txt", "path/file3", "home/user/docs/file2"},
		{"file5"},
	}
	for _, tCase := range cases {
		barPool, bars := NewBarPool(tCase, false)
		require.Len(t, bars, len(tCase))
		require.NotNil(t, barPool)
		for i := range tCase {
			require.Contains(t, bars[i].String(), filepath.Base(tCase[i]))
		}
	}
}

func TestBarPoolWithNonTerminalOutput(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	stderr := os.Stderr
	os.Stderr = output
	t.Cleanup(func() {
		os.Stderr = stderr
		output.Close()
	})

	pool, bars := NewBarPool([]string{"secret.txt"}, true)
	require.NoError(t, pool.Start())
	bar := bars[0]
	bar.SetTotal(4)
	_, err = bar.NewProxyWriter(io.Discard).Write([]byte("data"))
	require.NoError(t, err)
	require.Equal(t, int64(4), bar.Current())
	bar.Finish()
	require.NoError(t, pool.Stop())

	contents, err := os.ReadFile(output.Name())
	require.NoError(t, err)
	require.Empty(t, contents)
}
