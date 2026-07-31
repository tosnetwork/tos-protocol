package files

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

func DecodeJSON(path string, maxBytes int64, output interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return errors.New("file exceeds byte limit")
	}
	if err := jsonstrict.Decode(data, output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
