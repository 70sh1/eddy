package core

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/70sh1/eddy/format"
	"github.com/70sh1/eddy/pathutils"
	"github.com/cheggaaa/pb/v3"
)

type encryptor processor

// Reads up to len(b) bytes from encryptor's source (file) into buffer b, truncates it if n < len(b),
// XOR it, updates the encryptor's MAC with the resulting slice,
// returns number of bytes read and error.
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

func (e *encryptor) updateMac(data []byte) error {
	n, err := e.blake.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("could not write all bytes to mac")
	}
	return nil
}

func EncryptFile(pathIn, pathOut, password string, bar *pb.ProgressBar) error {
	processor, err := newProcessor(pathIn, password, Encryption)
	if err != nil {
		return err
	}
	enc := (*encryptor)(processor)
	defer enc.source.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer pathutils.CloseAndRemove(tmpFile)

	tagPlaceholder := make([]byte, enc.blake.Size())

	header := slices.Concat(enc.nonce, enc.scryptSalt, tagPlaceholder)
	if _, err := tmpFile.Write(header); err != nil {
		return err
	}

	bar.Set("filesize", format.FormatSize(enc.sourceSize))
	bar.SetTotal(enc.sourceSize)

	encryptorProxy := bar.NewProxyReader(enc)
	if _, err := io.Copy(tmpFile, encryptorProxy); err != nil {
		return err
	}

	tag := enc.blake.Sum(nil)
	if _, err := tmpFile.Seek(int64(headerLen-len(tag)), 0); err != nil {
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
