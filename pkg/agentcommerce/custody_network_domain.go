package agentcommerce

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// CustodyNetworkDomain is the exact NetworkDomainV1 projection shared by the
// Agent relay profile and custody authorization. NetworkID is an owner-pinned
// protocol label; the zero-state hashes and target WorkchainID prevent an RPC
// endpoint or same-labelled fork from authorizing itself.
//
// This compact duplicate deliberately lives in agentcommerce rather than
// importing agentrelay, which would create an import cycle. Cross-package tests
// freeze the byte-for-byte projection.
type CustodyNetworkDomain struct {
	NetworkID         string `json:"network_id"`
	GlobalID          int32  `json:"global_id"`
	ZeroStateRootHash string `json:"zero_state_root_hash"`
	ZeroStateFileHash string `json:"zero_state_file_hash"`
	WorkchainID       int32  `json:"workchain_id"`
}

func ValidateCustodyNetworkDomain(domain CustodyNetworkDomain) error {
	if !boundedIdentifier(domain.NetworkID, 128) || domain.GlobalID == 0 ||
		!canonicalDigestPattern.MatchString(domain.ZeroStateRootHash) ||
		!canonicalDigestPattern.MatchString(domain.ZeroStateFileHash) {
		return errors.New("custody network domain is invalid")
	}
	return nil
}

func writeCustodyNetworkDomain(output *bytes.Buffer, domain CustodyNetworkDomain) {
	writeLP32String(output, domain.NetworkID)
	_ = binary.Write(output, binary.BigEndian, domain.GlobalID)
	writeLP32String(output, domain.ZeroStateRootHash)
	writeLP32String(output, domain.ZeroStateFileHash)
	_ = binary.Write(output, binary.BigEndian, domain.WorkchainID)
}

func validateCustodyAuthorizationNetwork(schemaVersion uint16, networkID string, globalID int32,
	domain *CustodyNetworkDomain) error {
	switch schemaVersion {
	case 1:
		if globalID == 0 || domain != nil {
			return errors.New("legacy custody authorization network is invalid")
		}
	case 2, 3:
		if domain == nil || ValidateCustodyNetworkDomain(*domain) != nil ||
			domain.NetworkID != networkID || domain.GlobalID != globalID {
			return errors.New("domain-bound custody authorization network is invalid")
		}
	default:
		return errors.New("custody authorization schema is unsupported")
	}
	return nil
}
