package format

import "fmt"

const (
	kib = 1024
	mib = kib * 1024
	gib = mib * 1024
)

// Conditional prefix.
func CondPrefix(prefix string, s string, withoutPrefix bool) string {
	if withoutPrefix {
		return s
	}
	return prefix + s
}

func FormatSize(b int64) string {
	switch {
	case b >= gib:
		return fmt.Sprintf("(%.02f GiB)", float64(b)/gib)
	case b >= mib:
		return fmt.Sprintf("(%.02f MiB)", float64(b)/mib)
	case b >= kib:
		return fmt.Sprintf("(%.02f KiB)", float64(b)/kib)
	default:
		return fmt.Sprintf("(%d B)", b)
	}
}
