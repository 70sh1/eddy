package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/70sh1/eddy/core"
	"github.com/stretchr/testify/require"
)

func TestHeadlessCLIHelper(t *testing.T) {
	if os.Getenv("EDDY_TEST_HEADLESS_HELPER") != "1" {
		return
	}
	os.Args = append([]string{"eddy"}, os.Args[3:]...)
	main()
}

func TestHeadlessCLI(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	run := func(password string, args []string, failure string) {
		t.Helper()
		commandArgs := []string{"-test.run=^TestHeadlessCLIHelper$", "--", "-n", "--unsafe-password", password}
		cmd := exec.Command(executable, append(commandArgs, args...)...)
		cmd.Env = append(os.Environ(), "EDDY_TEST_HEADLESS_HELPER=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if failure == "" {
			require.NoError(t, err, stderr.String())
			require.Contains(t, stdout.String(), "Done in")
			require.Empty(t, stderr.String())
		} else {
			var exitError *exec.ExitError
			require.ErrorAs(t, err, &exitError)
			require.Equal(t, 1, exitError.ExitCode())
			require.Contains(t, stderr.String(), failure)
			require.NotContains(t, stdout.String(), "Done in")
		}
		require.NotContains(t, stderr.String(), "\x1b")
		require.NotContains(t, stderr.String(), "\r")
	}

	dir := t.TempDir()
	input := filepath.Join(dir, "secret.txt")
	plaintext := []byte("headless encryption and decryption")
	require.NoError(t, os.WriteFile(input, plaintext, 0o600))
	run("password", []string{"e", input}, "")
	run("password", []string{"e", input}, "output already exists")
	run("password", []string{"-w", "e", input}, "")
	run("password", []string{"e", filepath.Join(dir, "missing")}, "file not found")

	outputDir := filepath.Join(dir, "decrypted")
	require.NoError(t, os.Mkdir(outputDir, 0o700))
	run("wrong-password", []string{"-o", outputDir, "d", input + ".eddy"}, "incorrect password")
	require.NoFileExists(t, filepath.Join(outputDir, "secret.txt"))
	run("password", []string{"-o", outputDir, "d", input + ".eddy"}, "")
	run("password", []string{"-w", "-o", outputDir, "d", input + ".eddy"}, "")
	actual, err := os.ReadFile(filepath.Join(outputDir, "secret.txt"))
	require.NoError(t, err)
	require.Equal(t, plaintext, actual)
	actual, err = os.ReadFile(input)
	require.NoError(t, err)
	require.Equal(t, plaintext, actual)
}

func TestGenerateCLI(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	run := func(t *testing.T, args ...string) (string, string, error) {
		t.Helper()
		commandArgs := []string{"-test.run=^TestHeadlessCLIHelper$", "--", "-n"}
		cmd := exec.Command(executable, append(commandArgs, args...)...)
		cmd.Env = append(os.Environ(), "EDDY_TEST_HEADLESS_HELPER=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	t.Run("requested length", func(t *testing.T) {
		stdout, stderr, err := run(t, "generate", "6")
		require.NoError(t, err, stderr)
		require.Len(t, strings.Split(strings.TrimSpace(stdout), "-"), 6)
		require.Empty(t, stderr)
	})

	for _, tc := range []struct {
		name    string
		arg     string
		failure string
	}{
		{"non-number", "six", "must be a number"},
		{"insecure length", "5", "length less than 6 is not secure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := run(t, "generate", tc.arg)
			var exitError *exec.ExitError
			require.ErrorAs(t, err, &exitError)
			require.Equal(t, 1, exitError.ExitCode())
			require.Empty(t, stdout)
			require.Contains(t, stderr, tc.failure)
			require.NotContains(t, stderr, "\x1b")
		})
	}
}

func TestOutputPaths(t *testing.T) {
	for _, mode := range []core.Mode{core.Encryption, core.Decryption} {
		t.Run(map[core.Mode]string{core.Encryption: "encrypt", core.Decryption: "decrypt"}[mode], func(t *testing.T) {
			dir := t.TempDir()
			paths := []string{filepath.Join(dir, "one"), filepath.Join(dir, "two.eddy")}
			outputs, err := outputPaths(paths, "", mode)
			require.NoError(t, err)
			if mode == core.Encryption {
				require.Equal(t, []string{paths[0] + ".eddy", paths[1] + ".eddy"}, outputs)
			} else {
				require.Equal(t, []string{paths[0], filepath.Join(dir, "two")}, outputs)
			}
		})
	}
}

func TestCLIRejectsDuplicateOutputsBeforeProcessing(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, mode := range []string{"e", "d"} {
		for _, overwrite := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "", true: "/overwrite"}[overwrite], func(t *testing.T) {
				dir := t.TempDir()
				left := filepath.Join(dir, "left")
				right := filepath.Join(dir, "right")
				out := filepath.Join(dir, "out")
				for _, path := range []string{left, right, out} {
					require.NoError(t, os.Mkdir(path, 0o700))
				}
				first := filepath.Join(left, "report")
				second := filepath.Join(right, "report")
				if mode == "d" {
					// Distinct input basenames map to the same decrypted name.
					first += ".eddy"
				}
				for _, path := range []string{first, second} {
					require.NoError(t, os.WriteFile(path, []byte("unchanged input"), 0o600))
				}
				args := []string{"-test.run=^TestHeadlessCLIHelper$", "--", "-n", "-o", out}
				if overwrite {
					args = append(args, "-w")
				}
				// No password supplied: a duplicate must fail before the prompt.
				cmd := exec.Command(executable, append(args, mode, first, second)...)
				cmd.Env = append(os.Environ(), "EDDY_TEST_HEADLESS_HELPER=1")
				result, err := cmd.CombinedOutput()
				var exitError *exec.ExitError
				require.ErrorAs(t, err, &exitError)
				require.Equal(t, 1, exitError.ExitCode())
				require.Contains(t, string(result), "duplicate output destinations")
				entries, err := os.ReadDir(out)
				require.NoError(t, err)
				require.Empty(t, entries)
				for _, path := range []string{first, second} {
					actual, err := os.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, "unchanged input", string(actual))
				}
			})
		}
	}
}
