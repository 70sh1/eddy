package core

import (
	"crypto/subtle"
	"errors"
	"fmt"
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

// Read up to len(b) bytes from decryptor's source (file) into buffer b, truncate it if n < len(b),
// XOR it and return number of bytes read and error.
func (d *decryptor) Read(b []byte) (int, error) {
	n, err := d.source.Read(b)
	if n > 0 {
		b = b[:n]
		d.c.XORKeyStream(b, b)
		return n, err
	}
	return 0, io.EOF
}

// Verify a file via MAC tag. pb.Reader is used in order to show progress on the bar.
// Should be called before decryption.
func verifyFile(r *pb.Reader, dec *decryptor) (bool, error) {
	expectedTag := make([]byte, 64)
	n, err := dec.source.Read(expectedTag)
	if n != 64 || err != nil {
		return false, err
	}

	if _, err := io.Copy(dec.hmac, r); err != nil {
		return false, err
	}

	// Reset file offset back to the header end
	if _, err := dec.source.Seek(92, 0); err != nil {
		return false, err
	}

	actualTag := dec.hmac.Sum(nil)
	if subtle.ConstantTimeCompare(expectedTag, actualTag) != 1 {
		return false, nil
	}

	return true, nil
}

func decryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := NewProcessor(pathIn, password, "dec")
	if err != nil {
		return err
	}
	decryptor := &decryptor{processor}
	defer decryptor.source.Close()

	bar.Set("filesize", formatSize(decryptor.sourceSize))
	// We will go through the file twice so the progress bar total should be double the file size
	bar.SetTotal(decryptor.sourceSize * 2)

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer closeAndRemove(tmpFile)

	sourceProxy := bar.NewProxyReader(decryptor.source)
	defer sourceProxy.Close()
	fileIsValid, err := verifyFile(sourceProxy, decryptor)
	if err != nil {
		return fmt.Errorf("error verifying file; %v", err)
	}
	if !fileIsValid {
		err = errors.New("incorrect password or corrupt/forged data")
		return err
	}

	decryptorProxy := bar.NewProxyReader(decryptor)
	defer decryptorProxy.Close()
	if _, err := io.Copy(tmpFile, decryptorProxy); err != nil {
		return err
	}

	tmpFile.Close()
	decryptor.source.Close()

	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}

func DecryptFiles(paths []string, outputDir, password string, overwrite bool, noEmoji bool) error {
	var wg sync.WaitGroup

	barPool, bars := newBarPool(paths, noEmoji)
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
				barFail(bar, errors.New("output already exists"), noEmoji)
				return
			}
			if err := decryptFile(fileIn, fileOut, password, bar); err != nil {
				barFail(bar, err, noEmoji)
				return
			}
			bar.SetCurrent(bar.Total())
			bar.Set("status", "🔓")
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
