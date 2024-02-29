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

	"github.com/70sh1/eddy/core/bars"
	"github.com/70sh1/eddy/core/format"
	"github.com/70sh1/eddy/core/pathutils"
	"github.com/cheggaaa/pb/v3"
)

type decryptor struct {
	*processor
}

// Reads up to len(b) bytes from decryptor's source (file) into buffer b, truncates it if n < len(b),
// XORs it and returns number of bytes read and error.
func (d *decryptor) Read(b []byte) (int, error) {
	n, err := d.source.Read(b)
	if n > 0 {
		b = b[:n]
		d.c.XORKeyStream(b, b)
		return n, err
	}
	return 0, io.EOF
}

// Calculates the MAC tag of the given file and compares it with the expected tag.
// Should be called before decryption.
func verifyFile(dec *decryptor, expectedTag []byte, bar *pb.ProgressBar) (bool, error) {
	sourceProxy := bar.NewProxyReader(dec.source)
	if _, err := io.Copy(dec.blake, sourceProxy); err != nil {
		return false, err
	}

	// Reset file offset back to the header end
	if _, err := dec.source.Seek(headerLen, 0); err != nil {
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
	dec := &decryptor{processor}
	defer dec.source.Close()

	bar.Set("filesize", format.FormatSize(dec.sourceSize))
	// We will go through the file twice so the progress bar total should be double the file size
	bar.SetTotal(dec.sourceSize * 2)

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer pathutils.CloseAndRemove(tmpFile)

	// Verify file
	expectedTag := make([]byte, 64)
	n, err := io.ReadFull(dec.source, expectedTag)
	if n != 64 {
		return fmt.Errorf("failed to read MAC tag; %v", err)
	}
	fileIsValid, err := verifyFile(dec, expectedTag, bar)
	if err != nil {
		return fmt.Errorf("error verifying file; %v", err)
	}
	if !fileIsValid {
		err = errors.New("incorrect password or corrupt/forged data")
		return err
	}

	// Decrypt
	decryptorProxy := bar.NewProxyReader(dec)
	if _, err := io.Copy(tmpFile, decryptorProxy); err != nil {
		return err
	}

	tmpFile.Close()
	dec.source.Close()

	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}

func DecryptFiles(paths []string, outputDir, password string, overwrite bool, noEmojiAndColor bool) error {
	var wg sync.WaitGroup

	barPool, pbars := bars.NewPool(paths, noEmojiAndColor)
	if err := barPool.Start(); err != nil {
		return err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := pbars[i]
		fileIn := paths[i]
		go func() {
			defer wg.Done()
			defer bar.Finish()
			fileOut := strings.TrimSuffix(fileIn, ".eddy")
			if outputDir != "" {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				bars.Fail(bar, errors.New("output already exists"), noEmojiAndColor)
				return
			}
			if err := decryptFile(fileIn, fileOut, password, bar); err != nil {
				bars.Fail(bar, err, noEmojiAndColor)
				return
			}
			bar.SetCurrent(bar.Total())
			bar.Set("status", format.ConditionalPrefix("🔓", "", noEmojiAndColor))
		}()
	}

	wg.Wait()
	barPool.Stop()
	return nil
}
