// Copyright 2018-2019 Jeremy Rand.

// This file is part of safetlsa.
//
// safetlsa is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// safetlsa is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with safetlsa.  If not, see
// <https://www.gnu.org/licenses/>.

package safetlsa

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/namecoin/ncdns/certdehydrate"
	"github.com/namecoin/x509-signature-splice/x509"
)

func GetCertFromTLSA(domain string, tlsa *dns.TLSA, parentDERBytes []byte, parentPrivateKey interface{}) ([]byte, error) {
	// CA not in user's trust store; public key; not hashed
	if tlsa.Usage == 2 && tlsa.Selector == 1 && tlsa.MatchingType == 0 {
		domain = strings.TrimSuffix(domain, " Domain CA")

		publicKeyBytes, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			return nil, fmt.Errorf("Error decoding public key from hex: %s", err)
		}

		// Generate domain CA
		domainCA, err := GenerateDomainCA(domain, publicKeyBytes, parentDERBytes, parentPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Error generating domain CA: %s", err)
		}

		return domainCA, nil
	}

	// End entity cert not in user's trust store; full certificate; not hashed
	if tlsa.Usage == 3 && tlsa.Selector == 0 && tlsa.MatchingType == 0 {
		untrustedCertBytes, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			return nil, fmt.Errorf("Error decoding certificate from hex: %s", err)
		}

		untrustedCert, err := x509.ParseCertificate(untrustedCertBytes)
		if err != nil {
			return nil, fmt.Errorf("Error parsing certificate: %s", err)
		}

		dehydratedCert, err := certdehydrate.DehydrateCert(untrustedCert)
		if err != nil {
			return nil, fmt.Errorf("Error dehydrating certificate: %s", err)
		}

		rehydratedCertTemplate, err := certdehydrate.RehydrateCert(dehydratedCert)
		if err != nil {
			return nil, fmt.Errorf("Error rehydrating certificate: %s", err)
		}

		rehydratedCertBytes, err := certdehydrate.FillRehydratedCertTemplate(*rehydratedCertTemplate, domain)
		if err != nil {
			return nil, fmt.Errorf("Error filling rehydrated certificate template: %s", err)
		}

		return rehydratedCertBytes, nil
	}

	return nil, fmt.Errorf("Unsupported TLSA parameters")
}
