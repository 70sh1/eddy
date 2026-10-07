package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
	run("password", []string{"e", filepath.Join(dir, "missing")}, "file not found")

	outputDir := filepath.Join(dir, "decrypted")
	require.NoError(t, os.Mkdir(outputDir, 0o700))
	run("wrong-password", []string{"-o", outputDir, "d", input + ".eddy"}, "incorrect password")
	require.NoFileExists(t, filepath.Join(outputDir, "secret.txt"))
	run("password", []string{"-o", outputDir, "d", input + ".eddy"}, "")
	actual, err := os.ReadFile(filepath.Join(outputDir, "secret.txt"))
	require.NoError(t, err)
	require.Equal(t, plaintext, actual)
	actual, err = os.ReadFile(input)
	require.NoError(t, err)
	require.Equal(t, plaintext, actual)
}
