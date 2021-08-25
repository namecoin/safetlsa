// Copyright 2018 Jeremy Rand.
//
// Based on https://golang.org/src/crypto/tls/generate_cert.go ,
// Copyright 2009 The Go Authors.

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// Returns cert, private key, error
// nolint: lll
func GenerateTLDExclusionCA(domain string, parentDERBytes []byte, parentPrivateKey interface{}) ([]byte, interface{}, error) {
	parentCert, err := x509.ParseCertificate(parentDERBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing parent certificate: %s", err)
	}

	//flag.Parse()

	//if len(*host) == 0 {
	//	log.Fatalf("Missing required --host parameter")
	//}

	var priv interface{}
	//var err error
	//switch *ecdsaCurve {
	//case "":
	//	priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	//case "P224":
	//	priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	//case "P256":
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//case "P384":
	//	priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	//case "P521":
	//	priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	//default:
	//	fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", *ecdsaCurve)
	//	os.Exit(1)
	//}
	if err != nil {
		//log.Fatalf("failed to generate private key: %s", err)
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	//var notBefore time.Time
	//if len(*validFrom) == 0 {
	//	notBefore = time.Now()
	//} else {
	//	notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
	//	if err != nil {
	//		fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
	//		os.Exit(1)
	//	}
	//}

	//notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		//log.Fatalf("failed to generate serial number: %s", err)
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "." + domain + " TLD Exclusion CA",
			SerialNumber: "Namecoin TLS Certificate",
		},
		NotBefore: time.Now().Add(-1 * ValidityShortTerm()),
		NotAfter:  time.Now().Add(43800 * time.Hour),

		IsCA: true,
		//KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		KeyUsage: x509.KeyUsageCertSign,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		PermittedDNSDomainsCritical: true,
		ExcludedDNSDomains:         []string{"." + domain},
	}

	//hosts := strings.Split(*host, ",")
	//for _, h := range hosts {
	//	if ip := net.ParseIP(h); ip != nil {
	//		template.IPAddresses = append(template.IPAddresses, ip)
	//	} else {
	//		template.DNSNames = append(template.DNSNames, h)
	//	}
	//}

	//if *isCA {
	//	template.IsCA = true
	//	template.KeyUsage |= x509.KeyUsageCertSign
	//}

	//derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, publicKey(priv), parentPrivateKey)
	if err != nil {
		//log.Fatalf("Failed to create certificate: %s", err)
		return nil, nil, fmt.Errorf("Failed to create certificate: %s", err)
	}

	//certOut, err := os.Create("cert.pem")
	//if err != nil {
	//	log.Fatalf("failed to open cert.pem for writing: %s", err)
	//}
	//pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	//certOut.Close()
	//log.Print("written cert.pem\n")

	//keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	//if err != nil {
	//	log.Print("failed to open key.pem for writing:", err)
	//	return
	//}
	//pem.Encode(keyOut, pemBlockForKey(priv))
	//keyOut.Close()
	//log.Print("written key.pem\n")

	return derBytes, priv, nil
}
