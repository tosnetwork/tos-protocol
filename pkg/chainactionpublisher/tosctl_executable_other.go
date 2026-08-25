//go:build !linux

package chainactionpublisher

import (
	"errors"
	"os"
)

func captureChainExecutableIdentity(string) (chainExecutableIdentity, error) {
	return chainExecutableIdentity{}, errors.New("production tosctl chain publisher is supported only on Linux")
}

func openVerifiedChainExecutable(string, chainExecutableIdentity) (*os.File, error) {
	return nil, errors.New("production tosctl chain publisher is supported only on Linux")
}
