package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/70sh1/eddy/bars"
	"github.com/70sh1/eddy/core"
	"github.com/70sh1/eddy/format"
	"github.com/70sh1/eddy/pathutils"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func main() {
	app := &cli.App{
		Name:    "eddy",
		Usage:   "simple and fast file encryption",
		Version: "1.2.4",
		Authors: []*cli.Author{
			{Name: "70sh1", Email: "70sh1@proton.me"},
		},
		UseShortOptionHandling: true,
		Suggest:                true,
		Before: func(ctx *cli.Context) error {
			fmt.Println()
			// Remove date/time prefix from logger
			log.SetFlags(0)
			// Only logging errors with log.Fatal so this prefix is set
			noEmojiAndColor := ctx.Bool("no-emoji")
			logPrefix := "ERROR: "
			if !noEmojiAndColor {
				logPrefix = color.RedString(logPrefix)
			}
			log.SetPrefix(format.CondPrefix("❗ ", logPrefix, noEmojiAndColor))
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "specify output directory `PATH`",
			},
			&cli.IntFlag{
				Name:        "passgenlen",
				Aliases:     []string{"g"},
				Usage:       "specify generated passphrase `LENGTH`",
				DefaultText: "6",
			},
			&cli.BoolFlag{
				Name:    "overwrite",
				Aliases: []string{"w"},
				Usage:   "overwrite existing files",
			},
			&cli.BoolFlag{
				Name:    "no-emoji",
				Aliases: []string{"n"},
				Usage:   "disable emojis in output",
			},
			&cli.StringFlag{
				Name:  "unsafe-password",
				Usage: "replace password prompt with the provided `PASSWORD`",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"enc", "e"},
				Usage:   "Encrypts provided files",
				Action:  encrypt,
			},
			{
				Name:    "decrypt",
				Aliases: []string{"dec", "d"},
				Usage:   "Decrypts provided files",
				Action:  decrypt,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func askPassword(mode core.Mode, noEmojiAndColor bool) (string, error) {
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

func printDoneMessage(startTime time.Time, noEmojiAndColor bool) {
	fmt.Println()
	deltaTime := time.Since(startTime).Round(time.Millisecond)
	fmt.Printf(format.CondPrefix("✨ ", "Done in %v\n", noEmojiAndColor), deltaTime)
}

func encrypt(cCtx *cli.Context) error {
	var noPasswordProvided bool
	var numProcessed uint64
	var err error

	outputDir := cCtx.String("output")
	passGenLen := cCtx.Int("passgenlen")
	overwrite := cCtx.Bool("overwrite")
	noEmojiAndColor := cCtx.Bool("no-emoji")
	password := cCtx.String("unsafe-password")
	paths := append(cCtx.Args().Tail(), cCtx.Args().First())

	if paths, outputDir, err = pathutils.CleanAndCheckPaths(paths, outputDir); err != nil {
		return err
	}
	if password == "" && passGenLen == 0 {
		if password, err = askPassword(core.Encryption, noEmojiAndColor); err != nil {
			return err
		}
		passGenLen = 6
	}

	startTime := time.Now()
	if password == "" {
		if password, err = core.GeneratePassphrase(passGenLen); err != nil {
			return fmt.Errorf("failed to generate passphrase; %v", err)
		}
		noPasswordProvided = true
	}

	numProcessed, err = EncryptFiles(paths, outputDir, password, overwrite, noEmojiAndColor)
	if err != nil {
		return err
	}
	if noPasswordProvided && (numProcessed > 0) {
		fmt.Println()
		fmt.Printf(
			format.CondPrefix("🔑 ", "NOTE: This passphrase was generated and used: '%v'\n", noEmojiAndColor), password,
		)
	}
	printDoneMessage(startTime, noEmojiAndColor)

	return nil
}

func EncryptFiles(paths []string, outputDir, password string, overwrite, noEmojiAndColor bool) (uint64, error) {
	var wg sync.WaitGroup
	var numProcessed atomic.Uint64

	barPool, pbars := bars.NewPool(paths, noEmojiAndColor)
	if err := barPool.Start(); err != nil {
		return 0, err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := pbars[i]
		fileIn := paths[i]
		go func() {
			defer wg.Done()
			defer bar.Finish()
			fileOut := fileIn + ".eddy"
			if outputDir != "" {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				bars.Fail(bar, errors.New("output already exists"), noEmojiAndColor)
				return
			}
			if err := core.EncryptFile(fileIn, fileOut, password, bar); err != nil {
				bars.Fail(bar, err, noEmojiAndColor)
				return
			}
			bar.SetCurrent(bar.Total())
			bar.Set("status", format.CondPrefix("🔒", "", noEmojiAndColor))
			numProcessed.Add(1)
		}()
	}

	wg.Wait()
	barPool.Stop()
	return numProcessed.Load(), nil
}

func decrypt(cCtx *cli.Context) error {
	var err error

	outputDir := cCtx.String("output")
	overwrite := cCtx.Bool("overwrite")
	noEmojiAndColor := cCtx.Bool("no-emoji")
	password := cCtx.String("unsafe-password")
	paths := append(cCtx.Args().Tail(), cCtx.Args().First())

	if paths, outputDir, err = pathutils.CleanAndCheckPaths(paths, outputDir); err != nil {
		return err
	}
	if password == "" {
		if password, err = askPassword(core.Decryption, noEmojiAndColor); err != nil {
			return err
		}
	}

	startTime := time.Now()
	if err := decryptFiles(paths, outputDir, password, overwrite, noEmojiAndColor); err != nil {
		return err
	}
	printDoneMessage(startTime, noEmojiAndColor)

	return nil
}

func decryptFiles(paths []string, outputDir, password string, overwrite, noEmojiAndColor bool) error {
	var wg sync.WaitGroup

	barPool, pbars := bars.NewPool(paths, noEmojiAndColor)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := pbars[i]
		fileIn := paths[i]
		go func() {
			defer wg.Done()
			defer bar.Finish()
			fileOut := strings.TrimSuffix(fileIn, ".eddy")
			if outputDir != "" {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				bars.Fail(bar, errors.New("output already exists"), noEmojiAndColor)
				return
			}
			if err := core.DecryptFile(fileIn, fileOut, password, bar); err != nil {
				bars.Fail(bar, err, noEmojiAndColor)
				return
			}
			bar.SetCurrent(bar.Total())
			bar.Set("status", format.CondPrefix("🔓", "", noEmojiAndColor))
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
