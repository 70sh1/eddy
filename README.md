<h1 align="center">eddy :tornado:</h1>


<p align="center">
<a href="https://go.dev"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/70sh1/eddy"></a>
<a href="https://goreportcard.com/report/github.com/70sh1/eddy"><img alt="Go code report card" src="https://goreportcard.com/badge/github.com/70sh1/eddy"></a>
<a href="https://github.com/70sh1/eddy/actions"><img alt="Tests status" src="https://github.com/70sh1/eddy/actions/workflows/run-tests.yml/badge.svg"></a>
<a href="https://github.com/70sh1/eddy/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green"></a>
</p>

_eddy_ is a simple and fast CLI file encryption tool. It features concurrent file processing while ensuring data authenticity and plausible deniability. It is also capable of generating secure [passphrases](#passphrase-generation).

### Examples
```
eddy e secret.txt
```
```
eddy --overwrite encrypt secret.txt secret2.txt
```
```
eddy -g 8 enc secret.txt
```
```
eddy -wo "home/Documents" dec secret.txt.eddy
```
```
eddy --unsafe-password supeR-$ecr3t enc "D:/stuff/secret.txt" secret2.txt
```
### Commands
`encrypt`, `enc`, `e` - encrypt provided files.

`decrypt`, `dec`, `d` - decrypt provided files.

### Flags
`--output, -o` - specify output directory.

`--passgenlen, -g` - specify generated passphrase length (6 is the minimum). 

`--overwrite, -w` - enable overwrite existing files.

`--no-emoji, -n` - disable emojis in output.

`--unsafe-password` - replace interactive password prompt with the provided value. Intended for scripts/automation and reading password from environment variables. The "unsafe" prefix here is to indicate that the provided value will likely stay in the shell command history which is not safe.

## Installation
Prebuilt binaries are available for **Windows, Linux, and macOS (both x86 and ARM)**: download the latest release from the [releases](https://github.com/70sh1/eddy/releases) page for the desired OS.

If you have [Go](https://go.dev/dl/) installed, the simplest way to get _eddy_ is to run:
```shell
go install github.com/70sh1/eddy@latest
```
## Passphrase generation
If no password (empty one) was provided during encryption (this includes lack of `--unsafe-password` flag and leaving interactive password prompt empty), _eddy_ will generate and use a secure passphrase (length of 6 by default). Additionally, if this flag is provided, the password prompt will be skipped automatically. The length can be adjusted using `--passgenlen (-g)` flag. The passphrase is generated using cryptohraphically secure PRNG provided by the OS and EFF's long wordlist. You can read more about passphrases [here](https://www.eff.org/dice).

## Tips & notes
- The maximum file size is **256 GiB**.
- It is safe to rename any files that are encrypted with _eddy_.

## How it works
_eddy_ leverages `ChaCha20` for encryption paired with `Blake2b` for data authentication (HMAC). The `scrypt` KDF is used for producing keys.

## Acknowledgements
[urfave/cli](https://github.com/urfave/cli) - CLI framework.

[pb](https://github.com/cheggaaa/pb) - Progress bars.
