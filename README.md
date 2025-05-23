<h1 align="center">eddy :tornado:</h1>


<p align="center">
  <a href="https://go.dev"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/70sh1/eddy"></a>
  <a href="https://goreportcard.com/report/github.com/70sh1/eddy"><img alt="Go code report card" src="https://goreportcard.com/badge/github.com/70sh1/eddy"></a>
  <a href="https://github.com/70sh1/eddy/actions"><img alt="Tests status" src="https://github.com/70sh1/eddy/actions/workflows/run-tests.yml/badge.svg"></a>
  <a href="https://github.com/70sh1/eddy/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green"></a>
</p>

<p align="center">
  <img width=1000 src="demo.gif" alt="demo" />
</p>

_eddy_ is a simple and fast CLI file encryption tool. It features concurrent file processing while ensuring data authenticity and plausible deniability. It is also capable of generating secure [passphrases](#passphrase-generation).

### Commands
`encrypt`, `enc`, `e` - encrypt provided files.

`decrypt`, `dec`, `d` - decrypt provided files.

`generate`, `gen`, `g` - generate a passphrase.

### Flags
`--output, -o` - specify output directory.

`--passgenlen, -g` - specify generated passphrase length (6 is the minimum). Ignored in decryption mode.

`--overwrite, -w` - enable overwrite existing files.

`--no-emoji, -n` - disable emojis and color in output.

`--force` - force decrypt. Bypasses file authentication and, inherently, the password check. Useful if the encrypted file is corrupt (damaged) but you still want to decrypt it.

`--unsafe-password` - replace interactive password prompt with the provided value. Intended for scripts/automation and reading password from environment variables. The "unsafe" prefix here is to indicate that the provided value will likely stay in the shell command history which is not safe.

### Examples
```
# encrypt a text file
eddy e secret.txt

# encrypt multiple files in parallel
eddy e secret.txt secret2.png secret3.mp4

# encrypt a text file using a random 8-word passphrase
eddy -g 8 enc secret.txt

# encrypt while overwriting output files (here it would be 'secret.txt.eddy')
eddy --overwrite encrypt secret.txt

# decrypt a file and put it into Documents folder
eddy -wo ./Documents dec secret.txt.eddy

# encrypt two files and put them both into the current folder
# using the password 'supeR-$ecr3t'
# without using any color or emojis in the output
eddy --unsafe-password "supeR-$ecr3t" --no-emoji -o . enc "D:/stuff/secret.txt" secret2.txt

# generate a 10-word passphrase without any en/decryption
eddy gen 10
```

## Installation
The following install options are available:

#### Prebuilt binaries (releases)
Prebuilt binaries are available for **Windows, Linux, and macOS (both x86 and ARM)**: download the latest release from the [releases](https://github.com/70sh1/eddy/releases) page for the desired OS.

#### via Go
If you have [Go](https://go.dev/dl/) installed, the simplest way to get _eddy_ is to run:
```shell
go install github.com/70sh1/eddy@latest
```
> If you are on Linux and using this method with the default Go installation parameters, make sure that go bin path is added to your PATH environment variable: e.g. `export PATH=$PATH:$HOME/go/bin`

#### Scoop
_eddy_ is available as a part of [70sh1's scoop bucket](https://github.com/70sh1/jug). To install, you first need to add the bucket:
```
scoop bucket add jug https://github.com/70sh1/jug
```
After that, run:
```
scoop install eddy
```
Alternatively, if you don't want to add the bucket, you can run this:
```
scoop install https://raw.githubusercontent.com/70sh1/jug/refs/heads/master/bucket/eddy.json
```

#### Arch Linux
_eddy_ is available as a [package in the AUR](https://aur.archlinux.org/packages/eddy). You can install it using an AUR helper (e.g. `yay`):
```
yay -S eddy
```

## Passphrase generation
If no password (empty one) was provided during encryption (this includes lack of `--unsafe-password` flag and leaving interactive password prompt empty), _eddy_ will generate and use a secure passphrase (length of 6 words by default). The length can be adjusted using `--passgenlen (-g)` flag. Additionally, if the `-g` flag is provided, the password prompt will be skipped automatically. The passphrase is generated using cryptohraphically secure PRNG provided by the OS and EFF's long wordlist. The `generate` command is also available for standalone generation.

 You can read more about passphrases [here](https://www.eff.org/dice).

## What this tool doesn't do
- _eddy_ doesn't delete input files.
- _eddy_ doesn't preserve file timestamps (creation date and date modified).
- _eddy_ doesn't use any methods to increase the resilience of a file, such as error correction code. Therefore, regular backups of important files are recommended.

## Tips & notes
- The maximum file size is **256 GiB**.
- It is safe to rename any files that are encrypted with _eddy_. This means that decryption does not require `.eddy` in the file name.


## How it works
_eddy_ leverages `ChaCha20` for encryption paired with keyed `BLAKE2b` for data authentication (MAC). The `scrypt` KDF is used for producing keys. You can read more about the internals in the [spec file](https://github.com/70sh1/eddy/blob/main/SPEC.md).

## Acknowledgements
[urfave/cli](https://github.com/urfave/cli) - CLI framework.

[cheggaaa/pb](https://github.com/cheggaaa/pb) - Progress bars.
