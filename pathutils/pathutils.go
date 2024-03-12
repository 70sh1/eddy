package pathutils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Checks whenever given slice of strings contains duplicates.
func hasDuplicates(s []string) bool {
	a := make(map[string]bool)
	for _, v := range s {
		if _, e := a[v]; !e {
			a[v] = true
		} else {
			return true
		}
	}
	return false
}

// Checks whenever given slice of paths contains duplicate filenames.
func hasDuplicateFilenames(s []string) bool {
	a := make(map[string]bool)
	for _, v := range s {
		if _, e := a[filepath.Base(v)]; !e {
			a[filepath.Base(v)] = true
		} else {
			return true
		}
	}
	return false
}

func FilenameOverflow(s string, n int) string {
	r := []rune(s)
	if len(r) < n {
		return s
	}
	return string(r[:n]) + "..."
}

// Cleans given paths and ouputDir and checks for duplicates.
// Also checks for duplicate filenames if outputDir is not empty.
// Returns cleaned paths or error if any of the checks failed.
func CleanAndCheckPaths(paths []string, outputDir string) ([]string, string, error) {
	if len(paths) == 1 && paths[0] == "" {
		return nil, "", errors.New("empty path sequence")
	}

	for i := 0; i < len(paths); i++ {
		paths[i] = filepath.Clean(paths[i])
	}

	if hasDuplicates(paths) {
		return nil, "", errors.New("duplicate paths are not allowed")
	}

	if outputDir != "" {
		outputDir = filepath.Clean(outputDir)
		fileInfo, err := os.Stat(outputDir)
		if err != nil {
			return nil, "", err
		}
		if !fileInfo.IsDir() {
			return nil, "", fmt.Errorf("'%s' is not a directory", filepath.Base(outputDir))
		}

		if hasDuplicateFilenames(paths) {
			return nil, "", errors.New("duplicate filenames are not allowed with output (-o) flag")
		}
	}

	return paths, outputDir, nil
}

func CloseAndRemove(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}
