package testutils

import (
	"os"
	"path/filepath"
)

func TestFilesSetup() string {
	tmpDir, err := os.MkdirTemp(".", "test-tmp-*")
	PanicIfErr(err)

	if err := os.Mkdir(filepath.Join(tmpDir, "dir1"), 0700); err != nil {
		panic(err)
	}

	f1, err := os.Create(filepath.Join(tmpDir, "small.txt"))
	PanicIfErr(err)
	defer f1.Close()
	if _, err := f1.Write([]byte("Hello, world.\nSome text!")); err != nil {
		panic(err)
	}

	f2, err := os.Create(filepath.Join(tmpDir, "big.txt"))
	PanicIfErr(err)
	defer f2.Close()
	if _, err := f2.Write(make([]byte, 10_485_760)); err != nil {
		panic(err)
	}

	f3, err := os.Create(filepath.Join(tmpDir, "empty.txt"))
	PanicIfErr(err)
	defer f3.Close()

	f5, err := os.Create(filepath.Join(tmpDir, "too-short.txt.eddy"))
	PanicIfErr(err)
	defer f5.Close()
	if _, err := f5.Write(make([]byte, 20)); err != nil {
		panic(err)
	}

	f6, err := os.Create(filepath.Join(tmpDir, "small.txt.eddy"))
	PanicIfErr(err)
	defer f6.Close()
	data := []byte{159, 21, 91, 197, 188, 218, 176, 90, 10, 110, 138, 23, 39, 152, 144, 26, 35, 122, 186, 87, 36, 248, 3, 230, 164, 17, 138, 182, 113, 220, 194, 163, 53, 58, 163, 57, 201, 213, 196, 205, 79, 204, 10, 223, 235, 18, 113, 176, 69, 50, 177, 184, 154, 71, 214, 152, 59, 120, 122, 110, 205, 213, 245, 240, 27, 106, 22, 68, 86, 125, 206, 108, 28, 82, 100, 17, 12, 30, 199, 215, 6, 60, 216, 244, 44, 84, 142, 118, 109, 63, 20, 96, 171, 160, 226, 33, 68, 13, 87, 200, 177, 239, 108, 135, 126, 146, 48, 141, 93, 23, 92, 63, 199, 216, 38, 167}
	if _, err := f6.Write(data); err != nil {
		panic(err)
	}

	f7, err := os.Create(filepath.Join(tmpDir, "header-only.txt.eddy"))
	PanicIfErr(err)
	defer f7.Close()
	if _, err := f7.Write(make([]byte, 92)); err != nil {
		panic(err)
	}
	return tmpDir
}

func TestFilesCleanup(tmpDir string) {
	os.RemoveAll(tmpDir)
}

func PanicIfErr(e error) {
	if e != nil {
		panic(e)
	}
}
