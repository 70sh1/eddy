package bars

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPool(t *testing.T) {
	cases := [][]string{
		{"file1", "path/file2.dat", "home/user/docs/file2"},
		{"C:/some/dir/file1.txt", "path/file3", "home/user/docs/file2"},
		{"file5"},
	}
	for _, tCase := range cases {
		barPool, bars := NewPool(tCase, false)
		require.Len(t, bars, len(tCase))
		require.NotNil(t, barPool)
		for i := 0; i < len(tCase); i++ {
			require.Contains(t, bars[i].String(), filepath.Base(tCase[i]))
		}
	}
}
