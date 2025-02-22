package pathutils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rivo/uniseg"
)

// Checks if the given slice of strings contains duplicates.
func hasDuplicates(s []string) bool {
	seen := make(map[string]struct{})
	for _, v := range s {
		if _, exists := seen[v]; exists {
			return true
		}
		seen[v] = struct{}{}
	}
	return false
}

// Checks if the given slice of strings contains duplicates.
func hasDuplicateFilenames(s []string) bool {
	seen := make(map[string]struct{})
	for _, v := range s {
		if _, exists := seen[filepath.Base(v)]; exists {
			return true
		}
		seen[filepath.Base(v)] = struct{}{}
	}
	return false
}

func FilenameOverflow(s string, n int) string {
	charCount := uniseg.GraphemeClusterCount(s)
	if charCount < n {
		return s
	}
	gr := uniseg.NewGraphemes(s)
	for range n {
		gr.Next()
	}
	_, to := gr.Positions()
	return s[:to] + "..."
}

// Cleans given paths and ouputDir (which is also assumed to be a path) and checks for duplicates.
// Also checks for duplicate filenames if outputDir is not empty.
// Returns cleaned paths or error if any of the checks failed.
func CleanAndCheckPaths(paths []string, outputDir string) ([]string, string, error) {
	if len(paths) == 1 && paths[0] == "" {
		return nil, "", errors.New("empty path sequence")
	}

	for i := range paths {
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

func OpenAndGetSize(path string) (*os.File, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, errors.New("file not found")
		}
		return nil, 0, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if fileInfo.IsDir() {
		file.Close()
		return nil, 0, errors.New("processing directories is not supported")
	}

	return file, fileInfo.Size(), nil
}

func CloseAndRemove(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}
