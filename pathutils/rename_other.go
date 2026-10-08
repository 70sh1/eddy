//go:build !darwin && !linux && !windows

package pathutils

func renameNoReplace(from, to string) error {
	return linkNoReplace(from, to)
}
