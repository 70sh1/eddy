package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cheggaaa/pb/v3"
)

type decryptor struct {
	*processor
}

// Read len(b) bytes from decryptor's source (file) into buffer b, truncate it if n < len(b),
// update HMAC with slice, XOR the slice,
// return number of bytes read and error.
func (d *decryptor) Read(b []byte) (int, error) {
	n, err := d.source.Read(b)
	if n > 0 {
		b = b[:n]
		if err := d.updateHmac(b); err != nil {
			return n, err
		}
		d.c.XORKeyStream(b, b)
		return n, err
	}
	return 0, io.EOF
}

func decryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := NewProcessor(pathIn, password, "dec")
	if err != nil {
		barFail(bar, err)
		return err
	}
	decryptor := &decryptor{processor}
	defer decryptor.source.Close()

	expectedTag := make([]byte, 64)
	n, err := decryptor.source.Read(expectedTag)
	if n != 64 || err != nil {
		barFail(bar, err)
		return err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		barFail(bar, err)
		return err
	}
	defer closeAndRemove(tmpFile)

	bar.Set("filesize", formatSize(decryptor.sourceSize))
	bar.SetTotal(decryptor.sourceSize)
	w := bar.NewProxyWriter(tmpFile)
	defer w.Close()

	if _, err := io.Copy(w, decryptor); err != nil {
		barFail(bar, err)
		return err
	}

	tmpFile.Close()
	decryptor.source.Close()

	actualTag := decryptor.hmac.Sum(nil)
	if !bytes.Equal(actualTag, expectedTag) {
		err = errors.New("incorrect password or corrupt/forged data")
		barFail(bar, err)
		return err
	}

	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		barFail(bar, err)
		return err
	}

	bar.SetCurrent(bar.Total())
	bar.Set("status", "🔓")
	return nil
}

func DecryptFiles(paths []string, outputDir, password string, overwrite bool) error {
	var wg sync.WaitGroup

	barPool, bars := newBarPool(paths)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		fileIn := paths[i]
		bar := bars[i]
		go func() {
			defer wg.Done()
			fileOut := strings.TrimSuffix(fileIn, ".eddy")
			if outputDir != "" {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				barFail(bar, errors.New("output already exists"))
				return
			}
			decryptFile(fileIn, fileOut, password, bar)
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
