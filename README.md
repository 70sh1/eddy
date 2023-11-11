<h1 align="center">eddy :tornado:</h1>

_eddy_ is a simple and fast CLI file encryption tool. It features concurrent file processing while ensuring data authenticity and plausible deniability. It is also capable of generating secure [passphrases](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases).

### Examples
```
eddy encrypt secret.txt
```
```
eddy -w e secret.txt secret2.txt
```
```
eddy -g 8 enc secret.txt
```
```
eddy -wo "home/Documents" dec secret.txt
```
```
eddy --unsafe-password supeR-$ecr3t enc "D:/stuff/secret.txt" secret2.txt
```
### Commands
`encrypt`, `enc`, `e` - encrypt provided files.

`decrypt`, `dec`, `d` - decrypt provided files.

### Flags
`--output, -o` - specify output directory.

`--overwrite, -w` - enable overwrite existing files.

`--passgenlen, -g` - specify generated passphrase length (6 is the minimum). 

`--unsafe-password` - replace interactive password prompt with the provided value. Intended for scripts/automation and reading password from environment variables. The "unsafe" prefix here is to indicate that the provided value will likely stay in the shell command history which is not safe.

## Installation
Prebuilt binaries are available for **Windows, Linux, and macOS (both x86 and ARM)**: download the latest release from the [releases](https://github.com/70sh1/eddy/releases) page for the desired OS.

If you have [Go](https://go.dev/dl/) installed, the simplest way to get _eddy_ is to run:
```shell
go install github.com/70sh1/eddy@latest
```
## Tips & notes
- The maximum file size is **256 GiB**.
- It is safe to rename any files that are encrypted with _eddy_.

## How it works
_eddy_ leverages `ChaCha20` for encryption paired with `Blake2b` for data authentication (HMAC). The `scrypt` KDF is used for producing keys.

## Acknowledgements
[urfave/cli](https://github.com/urfave/cli) - CLI framework.

[pb](https://github.com/cheggaaa/pb) - Progress bars.
