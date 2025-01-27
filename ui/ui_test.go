package ui

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
