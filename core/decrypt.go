package core

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/70sh1/eddy/pathutils"
)

type decryptor processor

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

// Reads the MAC tag from decryptor's underlying file, calculates the actual tag of the file and compares them.
// Should be called before decryption.
func (d *decryptor) verify(progress io.WriteCloser) (bool, error) {
	expectedTag := make([]byte, 64)
	n, err := io.ReadFull(d.source, expectedTag)
	if n != 64 {
		return false, fmt.Errorf("failed to read MAC tag; %v", err)
	}

	multi := io.MultiWriter(d.blake, progress)
	if _, err := io.CopyBuffer(multi, d.source, make([]byte, 2048*2048)); err != nil {
		return false, err
	}

	// Reset file offset back to the header end
	if _, err := d.source.Seek(headerLen, 0); err != nil {
		return false, err
	}

	actualTag := d.blake.Sum(nil)
	if subtle.ConstantTimeCompare(expectedTag, actualTag) != 1 {
		return false, nil
	}

	return true, nil
}

func DecryptFile(source *os.File, pathOut, password string, progress io.WriteCloser) error {
	processor, err := newProcessor(source, password, Decryption)
	if err != nil {
		return err
	}
	dec := (*decryptor)(processor)
	defer dec.source.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer pathutils.CloseAndRemove(tmpFile)

	// Verify file
	fileIsValid, err := dec.verify(progress)
	if err != nil {
		return fmt.Errorf("error verifying file; %v", err)
	}
	if !fileIsValid {
		err = errors.New("incorrect password or corrupt/forged data")
		return err
	}

	// Decrypt
	multi := io.MultiWriter(tmpFile, progress)
	if _, err := io.CopyBuffer(multi, dec, make([]byte, 2048*2048)); err != nil {
		return err
	}

	tmpFile.Close()
	source.Close()
	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}
