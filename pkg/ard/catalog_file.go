package ard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteCatalogFile atomically replaces one operator-owned local catalog file.
// The resulting file is mode 0600. It does not publish, upload, or register the
// catalog, and it refuses to replace symlinks or non-regular files.
func WriteCatalogFile(path string, catalog Catalog, limits Limits) error {
	if path == "" {
		return errors.New("empty ARD catalog output path")
	}
	if err := catalog.Validate(limits); err != nil {
		return fmt.Errorf("validate ARD catalog before writing: %w", err)
	}
	encoded, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ARD catalog: %w", err)
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > limits.MaxCatalogBytes {
		return errors.New("encoded ARD catalog exceeds byte limit")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect ARD catalog directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("ARD catalog parent is not a real directory")
	}
	if err := validateCatalogFileTarget(path); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".tos-ard-catalog-*")
	if err != nil {
		return fmt.Errorf("create temporary ARD catalog: %w", err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	closeTemporary := func() {
		_ = temporary.Close()
	}
	if err := temporary.Chmod(0o600); err != nil {
		closeTemporary()
		return fmt.Errorf("set temporary ARD catalog mode: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		closeTemporary()
		return fmt.Errorf("write temporary ARD catalog: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		closeTemporary()
		return fmt.Errorf("sync temporary ARD catalog: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary ARD catalog: %w", err)
	}
	if err := validateCatalogFileTarget(path); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace ARD catalog: %w", err)
	}
	keepTemporary = false
	directory, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("open ARD catalog directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync ARD catalog directory: %w", err)
	}
	return nil
}

func validateCatalogFileTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect ARD catalog target: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ARD catalog target is not a regular file")
	}
	return nil
}
