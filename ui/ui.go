package ui

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/70sh1/eddy/core"
	"github.com/70sh1/eddy/format"
	"github.com/70sh1/eddy/pathutils"
	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"golang.org/x/term"
)

// Creates new progress bar pool.
func NewBarPool(paths []string, noEmojiAndColor bool) (*pb.Pool, []*pb.ProgressBar) {
	barTmpl := `{{ string . "status" }} {{ string . "filename" }} {{ string . "filesize" }} {{ bar . "[" "-"  ">" " " "]" }} {{ string . "error" }}`
	bars := make([]*pb.ProgressBar, len(paths))
	for i, path := range paths {
		bar := pb.New64(1).SetTemplateString(barTmpl).SetWidth(90)
		bar.Set("status", format.CondPrefix("  ", "", noEmojiAndColor))
		bar.Set("filename", pathutils.FilenameOverflow(filepath.Base(path), 25))
		bars[i] = bar
	}
	return pb.NewPool(bars...), bars
}

func BarFail(bar *pb.ProgressBar, err error, noEmojiAndColor bool) {
	errText := err.Error()
	if !noEmojiAndColor {
		errText = color.RedString(errText)
	}
	bar.Set("status", format.CondPrefix("❌", "", noEmojiAndColor))
	bar.Set("error", errText)
}

func AskPassword(mode core.Mode, noEmojiAndColor bool) (string, error) {
	fmt.Print(format.CondPrefix("🔑 ", "Password: ", noEmojiAndColor))
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Print("\r")
	if mode == core.Encryption {
		fmt.Print(format.CondPrefix("🔑 ", "Confirm password: ", noEmojiAndColor))
		password2, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		if !slices.Equal(password, password2) {
			fmt.Print("\r")
			return "", errors.New("passwords do not match")
		}
	}

	return string(password), nil
}
