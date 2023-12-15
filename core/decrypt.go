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

// Calculates the MAC tag of the give file and compares it with the expected tag.
// Should be called before decryption.
func verifyFile(dec *decryptor, expectedTag []byte, bar *pb.ProgressBar) (bool, error) {
	sourceProxy := bar.NewProxyReader(dec.source)
	if _, err := io.Copy(dec.blake, sourceProxy); err != nil {
		return false, err
	}

	// Reset file offset back to the header end
	if _, err := dec.source.Seek(92, 0); err != nil {
		return false, err
	}

	actualTag := dec.blake.Sum(nil)
	if subtle.ConstantTimeCompare(expectedTag, actualTag) != 1 {
		return false, nil
	}

	return true, nil
}

func decryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := newProcessor(pathIn, password, decryption)
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

	// Verify file
	expectedTag := make([]byte, 64)
	n, err := io.ReadFull(decryptor.source, expectedTag)
	if n != 64 {
		return fmt.Errorf("failed to read MAC tag; %v", err)
	}
	fileIsValid, err := verifyFile(decryptor, expectedTag, bar)
	if err != nil {
		return fmt.Errorf("error verifying file; %v", err)
	}
	if !fileIsValid {
		err = errors.New("incorrect password or corrupt/forged data")
		return err
	}

	// Decrypt
	decryptorProxy := bar.NewProxyReader(decryptor)
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
			bar.Set("status", ConditionalPrefix("🔓", "", noEmoji))
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
