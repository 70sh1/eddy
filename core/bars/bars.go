package bars

import (
	"path/filepath"

	"github.com/70sh1/eddy/core/format"
	"github.com/70sh1/eddy/core/pathutils"
	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
)

// Creates new progress bar pool.
func NewPool(paths []string, noEmojiAndColor bool) (pool *pb.Pool, bars []*pb.ProgressBar) {
	barTmpl := `{{ string . "status" }} {{ string . "filename" }} {{ string . "filesize" }} {{ bar . "[" "-"  ">" " " "]" }} {{ string . "error" }}`
	for _, path := range paths {
		bar := pb.New64(1).SetTemplateString(barTmpl).SetWidth(90)
		bar.Set("status", format.ConditionalPrefix("  ", "", noEmojiAndColor))
		bar.Set("filename", pathutils.FilenameOverflow(filepath.Base(path), 25))
		bars = append(bars, bar)
	}
	return pb.NewPool(bars...), bars
}

func Fail(bar *pb.ProgressBar, err error, noEmojiAndColor bool) {
	errText := err.Error()
	if !noEmojiAndColor {
		errText = color.RedString(errText)
	}
	bar.Set("status", format.ConditionalPrefix("❌", "", noEmojiAndColor))
	bar.Set("error", errText)
}
