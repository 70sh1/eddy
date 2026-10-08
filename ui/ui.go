package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/70sh1/eddy/core"
	"github.com/70sh1/eddy/pathutils"
	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"golang.org/x/term"
)

type BarPool struct {
	pool    *pb.Pool
	started bool
}

// Emoji returns value unless emoji output is disabled.
func Emoji(value string, disabled bool) string {
	if disabled {
		return ""
	}
	return value
}

// Start enables terminal rendering when possible. Progress rendering is optional,
// so terminal setup failures must not prevent file processing.
func (p *BarPool) Start() error {
	if p.started || !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	if err := p.pool.Start(); err != nil {
		return nil
	}
	p.started = true
	return nil
}

func (p *BarPool) Stop() error {
	if !p.started {
		return nil
	}
	return p.pool.Stop()
}

// Creates new progress bar pool.
func NewBarPool(paths []string, noEmojiAndColor bool) (*BarPool, []*pb.ProgressBar) {
	barTmpl := `{{ string . "status" }} {{ string . "filename" }} {{ string . "filesize" }} {{ bar . "[" "-"  ">" " " "]" }} {{ string . "error" }}`
	bars := make([]*pb.ProgressBar, len(paths))
	for i, path := range paths {
		bar := pb.New64(1).SetTemplateString(barTmpl).SetWidth(90)
		bar.Set("status", Emoji("  ", noEmojiAndColor))
		bar.Set("filename", pathutils.FilenameOverflow(filepath.Base(path), 25))
		bars[i] = bar
	}
	return &BarPool{pool: pb.NewPool(bars...)}, bars
}

func BarFail(bar *pb.ProgressBar, err error, noEmojiAndColor bool) {
	errText := err.Error()
	if !noEmojiAndColor {
		errText = color.RedString(errText)
	}
	bar.Set("status", Emoji("❌", noEmojiAndColor))
	bar.Set("error", errText)
}

func AskPassword(mode core.Mode, noEmojiAndColor bool) (string, error) {
	fmt.Print(Emoji("🔑 ", noEmojiAndColor), "Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Print("\r")
	if mode == core.Encryption {
		fmt.Print(Emoji("🔑 ", noEmojiAndColor), "Confirm password: ")
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
