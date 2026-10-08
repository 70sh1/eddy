package pathutils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CheckDistinctOutputs rejects destinations that name the same directory entry.
// Private probes let the filesystem apply its own case and Unicode rules without
// creating or modifying any output files.
func CheckDistinctOutputs(paths []string) error {
	if len(paths) < 2 {
		return nil
	}
	type directory struct {
		info  os.FileInfo
		paths []string
	}
	var directories []*directory
	parents := make(map[string]*directory)
	for _, path := range paths {
		parent := filepath.Dir(path)
		dir := parents[parent]
		if dir == nil {
			info, err := os.Stat(parent)
			if err != nil {
				return fmt.Errorf("checking output directory: %w", err)
			}
			for _, candidate := range directories {
				if os.SameFile(info, candidate.info) {
					dir = candidate
					break
				}
			}
			if dir == nil {
				dir = &directory{info: info}
				directories = append(directories, dir)
			}
			parents[parent] = dir
		}
		dir.paths = append(dir.paths, path)
	}
	for _, dir := range directories {
		if len(dir.paths) < 2 {
			continue
		}
		if err := checkOutputNames(dir.paths); err != nil {
			return err
		}
	}
	return nil
}

func checkOutputNames(paths []string) error {
	probe, err := os.MkdirTemp(filepath.Dir(paths[0]), ".eddy-check-*")
	if err != nil {
		return fmt.Errorf("checking output names: %w", err)
	}
	defer os.RemoveAll(probe)
	for _, path := range paths {
		file, err := os.OpenFile(filepath.Join(probe, filepath.Base(path)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("duplicate output destinations are not allowed: %s", path)
		}
		if err != nil {
			return fmt.Errorf("checking output name %s: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// CheckOutputAvailable avoids processing a file whose destination is occupied.
// This is an early check only; CommitOutput enforces the policy atomically.
func CheckOutputAvailable(path string, overwrite bool) error {
	if overwrite {
		return nil
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = os.ErrExist
	}
	return outputError(err)
}

// CommitOutput closes a completed temporary file before publishing it. Without
// overwrite, publication atomically fails if any entry already occupies pathOut.
// The caller must arrange to remove the temporary file if publication fails.
func CommitOutput(file *os.File, pathOut string, overwrite bool) error {
	if err := file.Close(); err != nil {
		return err
	}
	var err error
	if overwrite {
		err = os.Rename(file.Name(), pathOut)
	} else {
		err = renameNoReplace(file.Name(), pathOut)
	}
	return outputError(err)
}

func outputError(err error) error {
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("output already exists (use -w to overwrite): %w", err)
	}
	return err
}

// A hard link publishes the complete file exclusively when the platform lacks
// an exclusive rename. Unsupported filesystems fail safely; never fall back to
// checking existence followed by an ordinary rename.
func linkNoReplace(from, to string) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	return os.Remove(from)
}
