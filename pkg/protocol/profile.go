package protocol

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxProfileVersions   = 32
	MaxProfileExtensions = 32
)

type ProfileRequest struct {
	ID                  string   `json:"id"`
	SupportedVersions   []string `json:"supportedVersions"`
	SupportedExtensions []string `json:"supportedExtensions,omitempty"`
}

type ProfileOffer struct {
	ID                 string   `json:"id"`
	Versions           []string `json:"versions"`
	CriticalExtensions []string `json:"criticalExtensions,omitempty"`
}

type NegotiatedProfile struct {
	ID         string   `json:"id"`
	Version    string   `json:"version"`
	Extensions []string `json:"extensions,omitempty"`
}

func NegotiateProfile(request ProfileRequest, offer ProfileOffer) (NegotiatedProfile, error) {
	if request.ID != offer.ID || !serviceIDPattern.MatchString(request.ID) {
		return NegotiatedProfile{}, errors.New("profile identifier mismatch")
	}
	requestVersions, err := parseVersionSet(request.SupportedVersions)
	if err != nil {
		return NegotiatedProfile{}, fmt.Errorf("client versions: %w", err)
	}
	offerVersions, err := parseVersionSet(offer.Versions)
	if err != nil {
		return NegotiatedProfile{}, fmt.Errorf("service versions: %w", err)
	}
	clientExtensions, err := parseExtensionSet(request.SupportedExtensions)
	if err != nil {
		return NegotiatedProfile{}, err
	}
	criticalExtensions, err := parseExtensionSet(offer.CriticalExtensions)
	if err != nil {
		return NegotiatedProfile{}, err
	}
	for extension := range criticalExtensions {
		if _, supported := clientExtensions[extension]; !supported {
			return NegotiatedProfile{}, fmt.Errorf("unsupported critical extension %q", extension)
		}
	}
	common := make([]semanticVersion, 0)
	for text, version := range requestVersions {
		if _, exists := offerVersions[text]; exists {
			common = append(common, version)
		}
	}
	if len(common) == 0 {
		return NegotiatedProfile{}, errors.New("no common profile version")
	}
	sort.Slice(common, func(a, b int) bool { return common[b].less(common[a]) })
	extensions := make([]string, 0, len(criticalExtensions))
	for extension := range criticalExtensions {
		extensions = append(extensions, extension)
	}
	sort.Strings(extensions)
	return NegotiatedProfile{
		ID:         request.ID,
		Version:    common[0].String(),
		Extensions: extensions,
	}, nil
}

type semanticVersion struct {
	major uint32
	minor uint32
	patch uint32
}

func parseVersionSet(values []string) (map[string]semanticVersion, error) {
	if len(values) == 0 || len(values) > MaxProfileVersions {
		return nil, fmt.Errorf("version list must contain 1..%d entries", MaxProfileVersions)
	}
	output := make(map[string]semanticVersion, len(values))
	for _, value := range values {
		version, err := parseSemanticVersion(value)
		if err != nil {
			return nil, err
		}
		canonical := version.String()
		if canonical != value {
			return nil, fmt.Errorf("version %q is not canonical", value)
		}
		if _, duplicate := output[value]; duplicate {
			return nil, fmt.Errorf("duplicate version %q", value)
		}
		output[value] = version
	}
	return output, nil
}

func parseSemanticVersion(value string) (semanticVersion, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return semanticVersion{}, fmt.Errorf("version %q must use MAJOR.MINOR.PATCH", value)
	}
	var output semanticVersion
	numbers := []*uint32{&output.major, &output.minor, &output.patch}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return semanticVersion{}, fmt.Errorf("version %q contains a non-canonical number", value)
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return semanticVersion{}, fmt.Errorf("version %q is invalid", value)
		}
		*numbers[index] = uint32(parsed)
	}
	return output, nil
}

func (v semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v semanticVersion) less(other semanticVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

func parseExtensionSet(values []string) (map[string]struct{}, error) {
	if len(values) > MaxProfileExtensions {
		return nil, errors.New("too many profile extensions")
	}
	output := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := boundedString("profile extension", value, 3, 256); err != nil {
			return nil, err
		}
		if strings.ContainsAny(value, " \t\r\n") {
			return nil, errors.New("profile extension contains whitespace")
		}
		if _, duplicate := output[value]; duplicate {
			return nil, fmt.Errorf("duplicate profile extension %q", value)
		}
		output[value] = struct{}{}
	}
	return output, nil
}
