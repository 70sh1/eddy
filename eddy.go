package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/70sh1/eddy/core"
	"github.com/70sh1/eddy/format"
	"github.com/70sh1/eddy/pathutils"
	"github.com/70sh1/eddy/ui"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "eddy",
		Usage:   "simple and fast file encryption",
		Version: "1.4.1",
		Authors: []*cli.Author{
			{Name: "70sh1", Email: "70sh1@proton.me"},
		},
		UseShortOptionHandling: true,
		Suggest:                true,
		OnUsageError:           onUsageError,
		Before: func(cCtx *cli.Context) error {
			// Remove date/time prefix from logger
			log.SetFlags(0)
			// Only logging errors with log.Fatal so this prefix is set
			noEmojiAndColor := cCtx.Bool("no-emoji")
			logPrefix := "ERROR: "
			if !noEmojiAndColor {
				logPrefix = "❗ " + color.RedString(logPrefix)
			}
			log.SetPrefix(logPrefix)
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
			&cli.BoolFlag{
				Name:  "force",
				Usage: "force decrypt (bypass file authentication)",
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
			{
				Name:    "generate",
				Aliases: []string{"gen", "g"},
				Usage:   "Generates a passhrase of the given length",
				Action:  generate,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func printDoneMessage(startTime time.Time, noEmojiAndColor bool) {
	fmt.Println()
	deltaTime := time.Since(startTime).Round(time.Millisecond)
	fmt.Printf(format.CondPrefix("✨ ", "Done in %v\n", noEmojiAndColor), deltaTime)
}

func encrypt(cCtx *cli.Context) error {
	var err error

	outputDir := cCtx.String("output")
	overwrite := cCtx.Bool("overwrite")
	passGenLen := cCtx.Int("passgenlen")
	noEmojiAndColor := cCtx.Bool("no-emoji")
	password := cCtx.String("unsafe-password")
	paths := append(cCtx.Args().Tail(), cCtx.Args().First())

	if paths, outputDir, err = pathutils.CleanAndCheckPaths(paths, outputDir); err != nil {
		return err
	}
	fmt.Println()
	if password == "" && passGenLen == 0 {
		if password, err = ui.AskPassword(core.Encryption, noEmojiAndColor); err != nil {
			return err
		}
		passGenLen = 6
	}

	startTime := time.Now()
	if password == "" {
		if password, err = core.GeneratePassphrase(passGenLen); err != nil {
			return fmt.Errorf("failed to generate passphrase; %w", err)
		}
		fmt.Printf(
			format.CondPrefix("🔑 ", "NOTE: using this passphrase: '%s'\n", noEmojiAndColor),
			password,
		)
		fmt.Println()
	}

	err = encryptFiles(paths, outputDir, password, overwrite, noEmojiAndColor)
	if err != nil {
		return err
	}
	printDoneMessage(startTime, noEmojiAndColor)

	return nil
}

func encryptFiles(paths []string, outputDir, password string, overwrite, noEmojiAndColor bool) error {
	var wg sync.WaitGroup

	barPool, pbars := ui.NewBarPool(paths, noEmojiAndColor)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := pbars[i]
		pathIn := paths[i]
		go func() {
			defer wg.Done()
			defer bar.Finish()
			pathOut := pathIn + ".eddy"
			if outputDir != "" {
				pathOut = filepath.Join(outputDir, filepath.Base(pathOut))
			}
			if _, err := os.Stat(pathOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				ui.BarFail(bar, errors.New("output already exists"), noEmojiAndColor)
				return
			}
			source, size, err := pathutils.OpenAndGetSize(pathIn)
			if err != nil {
				ui.BarFail(bar, err, noEmojiAndColor)
				return
			}
			defer source.Close()

			bar.SetTotal(size)
			bar.Set("filesize", format.FormatSize(size))
			barWriter := bar.NewProxyWriter(io.Discard)

			if err := core.EncryptFile(source, pathOut, password, barWriter); err != nil {
				ui.BarFail(bar, err, noEmojiAndColor)
				return
			}

			bar.SetCurrent(bar.Total())
			bar.Set("status", format.CondPrefix("🔒", "", noEmojiAndColor))
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}

//

func decrypt(cCtx *cli.Context) error {
	var err error

	force := cCtx.Bool("force")
	outputDir := cCtx.String("output")
	overwrite := cCtx.Bool("overwrite")
	noEmojiAndColor := cCtx.Bool("no-emoji")
	password := cCtx.String("unsafe-password")
	paths := append(cCtx.Args().Tail(), cCtx.Args().First())

	if paths, outputDir, err = pathutils.CleanAndCheckPaths(paths, outputDir); err != nil {
		return err
	}
	fmt.Println()
	if password == "" {
		if password, err = ui.AskPassword(core.Decryption, noEmojiAndColor); err != nil {
			return err
		}
	}

	startTime := time.Now()
	err = decryptFiles(paths, outputDir, password, overwrite, force, noEmojiAndColor)
	if err != nil {
		return err
	}
	printDoneMessage(startTime, noEmojiAndColor)

	return nil
}

func decryptFiles(paths []string, outputDir, password string, overwrite, force, noEmojiAndColor bool) error {
	var wg sync.WaitGroup

	barPool, pbars := ui.NewBarPool(paths, noEmojiAndColor)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := pbars[i]
		pathIn := paths[i]
		go func() {
			defer wg.Done()
			defer bar.Finish()
			pathOut := strings.TrimSuffix(pathIn, ".eddy")
			if outputDir != "" {
				pathOut = filepath.Join(outputDir, filepath.Base(pathOut))
			}
			if _, err := os.Stat(pathOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				ui.BarFail(bar, errors.New("output already exists"), noEmojiAndColor)
				return
			}
			source, size, err := pathutils.OpenAndGetSize(pathIn)
			if err != nil {
				ui.BarFail(bar, err, noEmojiAndColor)
				return
			}
			defer source.Close()

			// We will go through the file twice so the progress bar total should be double the file size
			bar.SetTotal(size * 2)
			bar.Set("filesize", format.FormatSize(size))
			barWriter := bar.NewProxyWriter(io.Discard)

			err = core.DecryptFile(source, pathOut, password, force, barWriter)
			if err != nil {
				ui.BarFail(bar, err, noEmojiAndColor)
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

func generate(cCtx *cli.Context) error {
	lengthArg := cCtx.Args().First()
	if lengthArg == "" {
		return cli.ShowSubcommandHelp(cCtx)
	}

	length, err := strconv.Atoi(lengthArg)
	if err != nil {
		return fmt.Errorf("error parsing '%s', must be a number", lengthArg)
	}

	passphrase, err := core.GeneratePassphrase(length)
	if err != nil {
		return fmt.Errorf("failed to generate passphrase: %w", err)
	}

	fmt.Println(passphrase)
	return nil
}

func onUsageError(cCtx *cli.Context, err error, isSubcommand bool) error {
	fmt.Printf("Incorrect Usage: %v\n", err)
	os.Exit(1)
	return nil
}
