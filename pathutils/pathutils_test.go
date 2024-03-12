package pathutils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/70sh1/eddy/testutils"
	"github.com/stretchr/testify/require"
)

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

func TestCleanAndCheckPaths(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)

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
			"",
		},
		{
			[]string{"C:\\something.txt", "H:/qq", "a", "/home/\\//user//test/some"},
			[]string{filepath.Clean("C:\\something.txt"), filepath.Clean("H:/qq"), filepath.Clean("a"), filepath.Clean("/home/\\//user//test/some")},
			"",
			"",
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
			".",
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
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
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
			[]string{"path/to/something", "path\\////to//\\/something2/", "file1"},
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

func TestCloseAndRemove(t *testing.T) {
	dir := testutils.TestFilesSetup()
	defer testutils.TestFilesCleanup(dir)
	file, err := os.Open(filepath.Join(dir, "small.txt"))
	if err != nil {
		file.Close()
		panic(err)
	}

	CloseAndRemove(file)

	require.NoFileExists(t, file.Name())
}
