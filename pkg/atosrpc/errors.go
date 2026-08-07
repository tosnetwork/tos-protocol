package atosrpc

import (
	"errors"
	"strings"

	"connectrpc.com/connect"
)

const errorCodeHeader = "Atos-Error-Code"

func rpcError(code connect.Code, stableCode, message string) error {
	stableCode = strings.TrimSpace(stableCode)
	message = strings.TrimSpace(message)
	if message == "" {
		message = stableCode
	}
	err := connect.NewError(code, errors.New(message))
	if stableCode != "" {
		err.Meta().Set(errorCodeHeader, stableCode)
	}
	return err
}

func invalid(stableCode, message string) error {
	return rpcError(connect.CodeInvalidArgument, stableCode, message)
}

func notFound(stableCode, message string) error {
	return rpcError(connect.CodeNotFound, stableCode, message)
}

func conflict(stableCode, message string) error {
	return rpcError(connect.CodeAlreadyExists, stableCode, message)
}

func failedPrecondition(stableCode, message string) error {
	return rpcError(connect.CodeFailedPrecondition, stableCode, message)
}

func unavailable(stableCode, message string) error {
	return rpcError(connect.CodeUnavailable, stableCode, message)
}
