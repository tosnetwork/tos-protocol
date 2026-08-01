package ard

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

var workerCatalogServiceIDPattern = regexp.MustCompile(
	`^[a-z0-9][a-z0-9._:-]{2,127}$`,
)

// DecodeWorkerCatalogExtension strictly decodes the known TOS Worker
// capability extension. Unknown ARD extensions remain opaque, but a present
// known extension must be completely valid.
func DecodeWorkerCatalogExtension(
	entry Entry,
) (WorkerCatalogExtension, bool, error) {
	raw, present := entry.Extensions[WorkerCatalogExtensionName]
	if !present {
		return WorkerCatalogExtension{}, false, nil
	}
	if entry.Type != workerCatalogEntryType {
		return WorkerCatalogExtension{}, true, errors.New(
			"Worker capability extension requires a TOS service entry",
		)
	}
	var extension WorkerCatalogExtension
	if err := jsonstrict.Decode(raw, &extension); err != nil {
		return WorkerCatalogExtension{}, true, fmt.Errorf(
			"decode Worker capability extension: %w", err,
		)
	}
	if extension.Version != WorkerCatalogExtensionVersion {
		return WorkerCatalogExtension{}, true, errors.New(
			"unsupported Worker capability extension version",
		)
	}
	if err := validateWorkerCatalogText(
		"terminal revision", extension.TerminalRevision, 1, 512,
	); err != nil {
		return WorkerCatalogExtension{}, true, err
	}
	if len(extension.Capabilities) == 0 || len(extension.Capabilities) > 128 {
		return WorkerCatalogExtension{}, true, errors.New(
			"Worker capability extension must contain 1..128 capabilities",
		)
	}
	seen := make(map[string]struct{}, len(extension.Capabilities))
	for index, capability := range extension.Capabilities {
		if err := validateWorkerCatalogCapability(capability); err != nil {
			return WorkerCatalogExtension{}, true, fmt.Errorf(
				"Worker capability extension capabilities[%d]: %w", index, err,
			)
		}
		key := capability.ServiceID + "\x00" + capability.Operation + "\x00" +
			capability.Model
		if _, duplicate := seen[key]; duplicate {
			return WorkerCatalogExtension{}, true, errors.New(
				"Worker capability extension contains a duplicate capability",
			)
		}
		seen[key] = struct{}{}
	}
	return extension, true, nil
}

func validateWorkerCatalogCapability(value WorkerCatalogCapability) error {
	if !workerCatalogServiceIDPattern.MatchString(value.ServiceID) {
		return errors.New("invalid serviceId")
	}
	for name, candidate := range map[string]string{
		"operation": value.Operation,
		"model":     value.Model,
	} {
		if err := validateWorkerCatalogText(name, candidate, 1, 256); err != nil {
			return err
		}
	}
	if !canonicalSHA256Digest(value.ModelDigest) {
		return errors.New("invalid model digest")
	}
	for name, candidate := range map[string]string{
		"runtime":          value.Runtime,
		"runtime revision": value.RuntimeRevision,
	} {
		if err := validateWorkerCatalogText(name, candidate, 1, 512); err != nil {
			return err
		}
	}
	for name, candidate := range map[string]string{
		"max input bytes":  value.MaxInputBytes,
		"max output bytes": value.MaxOutputBytes,
	} {
		parsed, err := strconv.ParseUint(candidate, 10, 64)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != candidate {
			return fmt.Errorf("%s is not a canonical positive uint64", name)
		}
	}
	return nil
}

func validateWorkerCatalogText(
	name, value string,
	minimum, maximum int,
) error {
	if len(value) < minimum || len(value) > maximum ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}
