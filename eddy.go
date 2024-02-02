package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/70sh1/eddy/core"
	"github.com/70sh1/eddy/core/format"
	"github.com/70sh1/eddy/core/pathutils"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func main() {
	app := &cli.App{
		Name:                   "eddy",
		Usage:                  "simple and fast file encryption",
		Version:                "1.2.4",
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
			log.SetPrefix(format.ConditionalPrefix("❗ ", logPrefix, noEmojiAndColor))
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

func scanPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\r")
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

func doneMessage(startTime time.Time, noEmojiAndColor bool) {
	fmt.Println()
	deltaTime := time.Since(startTime).Round(time.Millisecond)
	fmt.Printf(format.ConditionalPrefix("✨ ", "Done in %v\n", noEmojiAndColor), deltaTime)
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
		password, err = scanPassword(format.ConditionalPrefix("🔑 ", "Password: ", noEmojiAndColor))
		if err != nil {
			return err
		}
	}

	startTime := time.Now()
	if err := core.DecryptFiles(paths, outputDir, password, overwrite, noEmojiAndColor); err != nil {
		return err
	}
	doneMessage(startTime, noEmojiAndColor)

	return nil
}

func encrypt(cCtx *cli.Context) error {
	var noPasswordProvided bool
	var numProcessed int
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
		password, err = scanPassword(format.ConditionalPrefix("🔑 ", "Password: ", noEmojiAndColor))
		if err != nil {
			return err
		}
		password2, err := scanPassword(format.ConditionalPrefix("🔑 ", "Confirm password: ", noEmojiAndColor))
		if err != nil {
			return err
		}
		if password != password2 {
			return errors.New("passwords do not match")
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

	if numProcessed, err = core.EncryptFiles(paths, outputDir, password, overwrite, noEmojiAndColor); err != nil {
		return err
	}
	if noPasswordProvided && (numProcessed > 0) {
		fmt.Println()
		fmt.Printf(format.ConditionalPrefix("🔑 ", "NOTE: This passphrase was generated and used: '%v'\n", noEmojiAndColor), password)
	}
	doneMessage(startTime, noEmojiAndColor)

	return nil
}
