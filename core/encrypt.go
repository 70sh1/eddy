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
// XOR it, update the encryptor's MAC with the resulting slice,
// return number of bytes read and error.
func (e *encryptor) Read(b []byte) (int, error) {
	n, err := e.source.Read(b)
	if n > 0 {
		b = b[:n]
		e.c.XORKeyStream(b, b)
		if err := e.updateMac(b); err != nil {
			return n, err
		}
		return n, err
	}
	return 0, io.EOF
}

func (p *encryptor) updateMac(data []byte) error {
	n, err := p.blake.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("could not write all bytes to mac")
	}
	return nil
}

func encryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := newProcessor(pathIn, password, encryption)
	if err != nil {
		return err
	}
	enc := &encryptor{processor}
	defer enc.source.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer closeAndRemove(tmpFile)

	header := make([]byte, 0, headerLen)
	tagPlaceholder := make([]byte, enc.blake.Size())
	header = append(header, enc.nonce...)
	header = append(header, enc.scryptSalt...)
	header = append(header, tagPlaceholder...)

	if _, err := tmpFile.Write(header); err != nil {
		return err
	}

	bar.Set("filesize", formatSize(enc.sourceSize))
	bar.SetTotal(enc.sourceSize)

	encryptorProxy := bar.NewProxyReader(enc)
	if _, err := io.Copy(tmpFile, encryptorProxy); err != nil {
		return err
	}

	tag := enc.blake.Sum(nil)
	if _, err := tmpFile.Seek(int64(len(enc.nonce)+len(enc.scryptSalt)), 0); err != nil {
		return err
	}
	if _, err := tmpFile.Write(tag); err != nil {
		return err
	}

	tmpFile.Close()
	enc.source.Close()
	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}

func EncryptFiles(paths []string, outputDir, password string, overwrite bool, noEmoji bool) (int, error) {
	var wg sync.WaitGroup
	var numProcessed int

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
			defer bar.Finish()
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
			bar.Set("status", ConditionalPrefix("🔒", "", noEmoji))
			numProcessed++
		}()
	}

	wg.Wait()
	barPool.Stop()
	return numProcessed, nil
}
