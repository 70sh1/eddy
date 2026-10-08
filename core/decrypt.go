package core

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/70sh1/eddy/pathutils"
)

func DecryptFile(source *os.File, pathOut, password string, force bool, progress io.Writer) error {
	sourceInfo, err := source.Stat()
	if err != nil {
		return fmt.Errorf("error checking input file: %w", err)
	}
	outputInfo, err := os.Stat(pathOut)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("error checking output file: %w", err)
	}
	if err == nil && os.SameFile(sourceInfo, outputInfo) {
		return errors.New("input and output refer to the same file; choose a different output directory")
	}

	processor, err := newProcessor(source, password, Decryption)
	if err != nil {
		return err
	}

	var expectedTag []byte
	var ciphertext io.Reader = source
	if force {
		if _, err := source.Seek(headerLen, io.SeekStart); err != nil {
			return err
		}
	} else {
		expectedTag = make([]byte, processor.blake.Size())
		if _, err := io.ReadFull(source, expectedTag); err != nil {
			return fmt.Errorf("error verifying file: failed to read MAC tag: %w", err)
		}
		// Hash the exact ciphertext bytes that StreamReader decrypts in place.
		ciphertext = io.TeeReader(source, processor.blake)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(pathOut), "*.tmp")
	if err != nil {
		return err
	}
	defer pathutils.CloseAndRemove(tmpFile)

	// Decrypt into the temporary file without publishing unauthenticated data.
	multi := io.MultiWriter(tmpFile, progress)
	reader := &cipher.StreamReader{S: processor.c, R: ciphertext}
	if _, err := io.CopyBuffer(multi, reader, make([]byte, bufSize)); err != nil {
		return err
	}

	if !force && subtle.ConstantTimeCompare(expectedTag, processor.blake.Sum(nil)) != 1 {
		return errors.New("incorrect password or corrupt/forged data")
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpFile.Name(), pathOut); err != nil {
		return err
	}

	return nil
}
