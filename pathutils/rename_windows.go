package pathutils

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func renameNoReplace(from, to string) error {
	old, err := windowsRenamePath(from)
	if err != nil {
		return err
	}
	new, err := windowsRenamePath(to)
	if err != nil {
		return err
	}
	// Omitting MOVEFILE_REPLACE_EXISTING makes the operation exclusive.
	if err := windows.MoveFileEx(old, new, 0); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

func windowsRenamePath(path string) (*uint16, error) {
	// Preserve ordinary Windows name normalization for short paths. Native
	// calls need an extended absolute path when the legacy path limit is hit.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if len(abs) >= 248 && !strings.HasPrefix(abs, `\\?\`) && !strings.HasPrefix(abs, `\\.\`) {
		if strings.HasPrefix(abs, `\\`) {
			path = `\\?\UNC\` + abs[2:]
		} else {
			path = `\\?\` + abs
		}
	}
	return windows.UTF16PtrFromString(path)
}
