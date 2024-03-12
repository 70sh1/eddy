package format

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
		result := FormatSize(tCase)
		require.Equal(t, expected, result)
	}
}
