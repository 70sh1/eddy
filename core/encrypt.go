package core

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
)

type encryptor struct {
	*processor
}

// Read up to len(b) bytes from encryptor's source (file) into buffer b, truncate it if n < len(b),
// XOR it, update the encryptor's HMAC with the resulting slice,
// return number of bytes read and error.
func (e *encryptor) Read(b []byte) (int, error) {
	n, err := e.source.Read(b)
	if n > 0 {
		b = b[:n]
		e.c.XORKeyStream(b, b)
		if err := e.updateHmac(b); err != nil {
			return n, err
		}
		return n, err
	}
	return 0, io.EOF
}

func encryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := NewProcessor(pathIn, password, "enc")
	if err != nil {
		return err
	}
	encryptor := &encryptor{processor}
	defer encryptor.source.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer closeAndRemove(tmpFile)

	var header []byte
	tagPlaceholder := make([]byte, encryptor.hmac.Size())
	header = append(header, encryptor.nonce...)
	header = append(header, encryptor.hmacSalt...)
	header = append(header, tagPlaceholder...)

	if _, err := tmpFile.Write(header); err != nil {
		return err
	}

	bar.Set("filesize", formatSize(encryptor.sourceSize))
	bar.SetTotal(encryptor.sourceSize)
	w := bar.NewProxyWriter(tmpFile)
	defer w.Close()

	if _, err := io.Copy(w, encryptor); err != nil {
		return err
	}

	tag := encryptor.hmac.Sum(nil)
	if _, err := tmpFile.Seek(int64(len(encryptor.nonce)+len(encryptor.hmacSalt)), 0); err != nil {
		return err
	}
	if _, err := tmpFile.Write(tag); err != nil {
		return err
	}

	tmpFile.Close()
	encryptor.source.Close()
	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}

func EncryptFiles(paths []string, outputDir, password string, overwrite bool, noEmoji bool) (int64, error) {
	var wg sync.WaitGroup
	var numProcessed int64

	barPool, bars := newBarPool(paths, noEmoji)
	if err := barPool.Start(); err != nil {
		return 0, err
	}

	wg.Add(len(paths))
	for i := 0; i < len(paths); i++ {
		bar := bars[i]
		fileIn := paths[i]
		go func() {
			defer wg.Done()
			fileOut := fileIn + ".eddy"
			if outputDir != "" {
				fileOut = filepath.Join(outputDir, filepath.Base(fileOut))
			}
			if _, err := os.Stat(fileOut); !errors.Is(err, os.ErrNotExist) && !overwrite {
				barFail(bar, errors.New("output already exists"), noEmoji)
				return
			}
			if err := encryptFile(fileIn, fileOut, password, bar); err != nil {
				barFail(bar, err, noEmoji)
				return
			}
			bar.SetCurrent(bar.Total())
			bar.Set("status", "🔒")
			numProcessed += 1
		}()
	}

	wg.Wait()
	barPool.Stop()
	return numProcessed, nil
}
