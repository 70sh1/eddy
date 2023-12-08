package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/70sh1/eddy/core"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func main() {
	var (
		password   string
		outputDir  string
		passGenLen int
		overwrite  bool
		noEmoji    bool
	)
	app := &cli.App{
		Name:                   "eddy",
		Usage:                  "simple and fast file encryption",
		Version:                "1.1.0",
		UseShortOptionHandling: true,
		Suggest:                true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Destination: &outputDir,
				Usage:       "specify output directory",
			},
			&cli.IntFlag{
				Name:        "passgenlen",
				Aliases:     []string{"g"},
				Destination: &passGenLen,
				Usage:       "specify generated passphrase length",
				DefaultText: "6",
			},
			&cli.BoolFlag{
				Name:        "overwrite",
				Aliases:     []string{"w"},
				Destination: &overwrite,
				Usage:       "overwrite existing files",
			},
			&cli.BoolFlag{
				Name:        "no-emoji",
				Aliases:     []string{"n"},
				Destination: &noEmoji,
				Usage:       "disable emojis in output",
			},
			&cli.StringFlag{
				Name:        "unsafe-password",
				Destination: &password,
				Usage:       "replaces password prompt with the provided password",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"enc", "e"},
				Usage:   "encrypt provided `FILES`",
				Action: func(cCtx *cli.Context) error {
					var noPasswordProvided bool
					var numProcessed int64
					var err error
					log.SetPrefix(core.ConditionalPrefix("❗ ", "ERROR: ", noEmoji)) // Only logging errors with log.Fatal so this prefix is set
					paths := append(cCtx.Args().Tail(), cCtx.Args().First())
					if paths, outputDir, err = core.CleanAndCheckPaths(paths, outputDir); err != nil {
						log.Fatal(err)
					}
					if !cCtx.IsSet("unsafe-password") {
						if !cCtx.IsSet("passgenlen") {
							password, err = scanPassword(core.ConditionalPrefix("🔑 ", "Password: ", noEmoji))
							if err != nil {
								log.Fatal(err)
							}
							password2, err := scanPassword(core.ConditionalPrefix("🔑 ", "Confirm password: ", noEmoji))
							if err != nil {
								log.Fatal(err)
							}
							if password != password2 {
								log.Fatal("passwords do not match")
							}
							passGenLen = 6
						}
						if len(password) < 1 {
							if password, err = core.GeneratePassphrase(passGenLen); err != nil {
								log.Fatalf("failed to generate passphrase; %v", err)
							}
							noPasswordProvided = true
						}
					}

					startTime := time.Now()
					if numProcessed, err = core.EncryptFiles(paths, outputDir, password, overwrite, noEmoji); err != nil {
						log.Fatal(err)
					}
					if noPasswordProvided && (numProcessed > 0) {
						fmt.Println()
						fmt.Printf(core.ConditionalPrefix("🔑 ", "NOTE: This passphrase was generated and used: '%v'\n", noEmoji), password)
					}
					deltaTime := time.Since(startTime).Round(time.Millisecond)
					fmt.Println()
					fmt.Printf(core.ConditionalPrefix("✨ ", "Done in %v\n", noEmoji), deltaTime)
					return nil
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"dec", "d"},
				Usage:   "decrypt provided `FILES`",
				Action: func(cCtx *cli.Context) error {
					var err error
					log.SetPrefix(core.ConditionalPrefix("❗ ", "ERROR: ", noEmoji))
					paths := append(cCtx.Args().Tail(), cCtx.Args().First())
					if paths, outputDir, err = core.CleanAndCheckPaths(paths, outputDir); err != nil {
						log.Fatal(err)
					}
					if !cCtx.IsSet("unsafe-password") {
						password, err = scanPassword(core.ConditionalPrefix("🔑 ", "Password: ", noEmoji))
						if err != nil {
							log.Fatal(err)
						}
					}

					startTime := time.Now()
					if err := core.DecryptFiles(paths, outputDir, password, overwrite, noEmoji); err != nil {
						log.Fatal(err)
					}
					deltaTime := time.Since(startTime).Round(time.Millisecond)
					fmt.Println()
					fmt.Printf(core.ConditionalPrefix("✨ ", "Done in %v\n", noEmoji), deltaTime)
					return nil
				},
			},
		},
	}
	log.SetFlags(0) // Remove date/time prefix from logger
	fmt.Println()
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
