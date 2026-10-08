package pathutils

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckDistinctOutputs(t *testing.T) {
	tests := []struct {
		name  string
		paths func(*testing.T, string) []string
	}{
		{"same name", func(t *testing.T, dir string) []string {
			return []string{filepath.Join(dir, "output"), filepath.Join(dir, "output")}
		}},
		{"relative alias", func(t *testing.T, dir string) []string {
			t.Chdir(dir)
			return []string{"output", filepath.Join(dir, "output")}
		}},
		{"symlinked parent", func(t *testing.T, dir string) []string {
			parent := filepath.Join(dir, "parent")
			require.NoError(t, os.Mkdir(parent, 0o700))
			alias := filepath.Join(dir, "alias")
			if err := os.Symlink(parent, alias); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			return []string{filepath.Join(parent, "output"), filepath.Join(alias, "output")}
		}},
		{"case-insensitive names", func(t *testing.T, dir string) []string {
			upper := filepath.Join(dir, "Output")
			lower := filepath.Join(dir, "output")
			require.NoError(t, os.WriteFile(upper, []byte("existing"), 0o600))
			if _, err := os.Stat(lower); errors.Is(err, os.ErrNotExist) {
				t.Skip("case-sensitive filesystem")
			}
			return []string{upper, lower}
		}},
		{"Unicode-equivalent names", func(t *testing.T, dir string) []string {
			composed := filepath.Join(dir, "caf\u00e9")
			decomposed := filepath.Join(dir, "cafe\u0301")
			require.NoError(t, os.WriteFile(composed, []byte("existing"), 0o600))
			if _, err := os.Stat(decomposed); errors.Is(err, os.ErrNotExist) {
				t.Skip("filesystem distinguishes Unicode spellings")
			}
			return []string{composed, decomposed}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := tc.paths(t, dir)
			before, err := os.ReadDir(filepath.Dir(paths[0]))
			require.NoError(t, err)
			require.ErrorContains(t, CheckDistinctOutputs(paths), "duplicate output destinations")
			after, err := os.ReadDir(filepath.Dir(paths[0]))
			require.NoError(t, err)
			require.Equal(t, before, after, "preflight must clean up its probes")
		})
	}

	t.Run("distinct outputs", func(t *testing.T) {
		dir := t.TempDir()
		other := t.TempDir()
		require.NoError(t, CheckDistinctOutputs([]string{
			filepath.Join(dir, "one"), filepath.Join(dir, "two"), filepath.Join(other, "one"),
		}))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Empty(t, entries)
	})
}

func TestCommitOutput(t *testing.T) {
	for _, kind := range []string{"missing", "file", "directory", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "output")
			switch kind {
			case "file":
				require.NoError(t, os.WriteFile(output, []byte("original"), 0o600))
			case "directory":
				require.NoError(t, os.Mkdir(output, 0o700))
			case "dangling symlink":
				if err := os.Symlink(filepath.Join(dir, "missing"), output); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			require.NoError(t, CheckOutputAvailable(output, true))
			if kind == "missing" {
				require.NoError(t, CheckOutputAvailable(output, false))
			} else {
				err := CheckOutputAvailable(output, false)
				require.ErrorIs(t, err, os.ErrExist)
				require.ErrorContains(t, err, "use -w")
			}
			file, err := os.CreateTemp(dir, "*.tmp")
			require.NoError(t, err)
			defer CloseAndRemove(file)
			_, err = file.WriteString("new content")
			require.NoError(t, err)
			err = CommitOutput(file, output, false)
			if kind == "missing" {
				require.NoError(t, err)
				actual, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, "new content", string(actual))
				return
			}
			require.ErrorIs(t, err, os.ErrExist)
			require.ErrorContains(t, err, "use -w")
			if kind == "file" {
				actual, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, "original", string(actual))
			}
			if kind == "directory" {
				require.DirExists(t, output)
			}
			if kind == "dangling symlink" {
				target, err := os.Readlink(output)
				require.NoError(t, err)
				require.Equal(t, filepath.Join(dir, "missing"), target)
			}
		})
	}
}

func TestCheckOutputAvailablePreservesFilesystemError(t *testing.T) {
	err := CheckOutputAvailable(filepath.Join(t.TempDir(), "invalid\x00"), false)
	var pathError *os.PathError
	require.ErrorAs(t, err, &pathError)
	require.NotErrorIs(t, err, os.ErrExist)
	require.NotContains(t, err.Error(), "output already exists")
}

func TestCommitOutputRejectsCloseFailure(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			name := "new destination"
			if existing {
				name = "existing destination"
			}
			if overwrite {
				name += "/overwrite"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				output := filepath.Join(dir, "output")
				if existing {
					require.NoError(t, os.WriteFile(output, []byte("original"), 0o600))
				}
				file, err := os.CreateTemp(dir, "*.tmp")
				require.NoError(t, err)
				defer CloseAndRemove(file)
				_, err = file.WriteString("replacement")
				require.NoError(t, err)
				// A closed handle makes Close fail deterministically without
				// requiring a filesystem that reports delayed write failures.
				require.NoError(t, file.Close())

				require.ErrorIs(t, CommitOutput(file, output, overwrite), os.ErrClosed)
				require.FileExists(t, file.Name(), "failed close must prevent publication")
				if existing {
					actual, err := os.ReadFile(output)
					require.NoError(t, err)
					require.Equal(t, "original", string(actual))
				} else {
					require.NoFileExists(t, output)
				}
			})
		}
	}
}

func TestConcurrentCommitHelper(t *testing.T) {
	if os.Getenv("EDDY_TEST_COMMIT_HELPER") != "1" {
		return
	}
	file, err := os.OpenFile(os.Args[3], os.O_RDWR, 0)
	if err != nil {
		os.Exit(2)
	}
	// Signal readiness only after both processes have complete staged files.
	os.Stdout.WriteString("ready\n")
	_, err = io.ReadFull(os.Stdin, make([]byte, 1))
	if err == nil {
		err = CommitOutput(file, os.Args[4], false)
	}
	CloseAndRemove(file)
	if errors.Is(err, os.ErrExist) {
		os.Exit(3)
	}
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestLinkNoReplaceFallback(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.tmp")
	second := filepath.Join(dir, "second.tmp")
	output := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(first, []byte("winner"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("loser"), 0o600))
	require.NoError(t, linkNoReplace(first, output))
	require.NoFileExists(t, first)
	require.ErrorIs(t, linkNoReplace(second, output), os.ErrExist)
	require.FileExists(t, second)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "winner", string(actual))
}

func TestConcurrentCommitsDoNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	executable, err := os.Executable()
	require.NoError(t, err)
	commands := make([]*exec.Cmd, 2)
	inputs := make([]io.WriteCloser, 2)
	for i, content := range []string{"first", "second"} {
		file, err := os.CreateTemp(dir, "*.tmp")
		require.NoError(t, err)
		_, err = file.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, file.Close())
		cmd := exec.Command(executable, "-test.run=^TestConcurrentCommitHelper$", "--", file.Name(), output)
		cmd.Env = append(os.Environ(), "EDDY_TEST_COMMIT_HELPER=1")
		inputs[i], err = cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		line, err := bufio.NewReader(stdout).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "ready\n", line)
		commands[i] = cmd
	}
	for _, stdin := range inputs {
		_, err := stdin.Write([]byte{1})
		require.NoError(t, err)
		require.NoError(t, stdin.Close())
	}
	winner := -1
	for i, cmd := range commands {
		err := cmd.Wait()
		if err == nil {
			require.Equal(t, -1, winner, "only one process may succeed")
			winner = i
		} else {
			var exitError *exec.ExitError
			require.ErrorAs(t, err, &exitError)
			require.Equal(t, 3, exitError.ExitCode(), "loser must get an existence error")
		}
	}
	require.NotEqual(t, -1, winner)
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}[winner], string(actual))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
