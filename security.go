// https://ss64.com/osx/security.html
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
)

type Keychain int

const (
	KeychainLogin Keychain = iota
	KeychainSystem
)

type SecurityTrustCert struct {
	// addToAdminCertStore bool
	resultType string // trustRoot|trustAsRoot|deny|unspecified; default is trustRoot.
	policy     string // Specify policy constraint; default is ssl.
	// appPath         string   // Specify application constraint.
	// policyString    string   // Specify policy-specific string.
	// allowedError    string   //Specify allowed error (an integer value, or one of: certExpired, hostnameMismatch) match)
	// keyUsage        int      // Specify key usage, an integer.
	keychain Keychain // Specify keychain to which cert is added. default is login keychain
	// settingsFileIn  string   // Input trust settings file; default is user domain.
	// settingsFileOut string   // Output trust settings file; default is user domain.
	keychainPath string
	err          error
	certPath     string
}

func NewSecurityTrustCert() *SecurityTrustCert {
	return &SecurityTrustCert{}
}

func (s *SecurityTrustCert) setKeychainType(kc Keychain) *SecurityTrustCert {
	s.keychain = kc
	return s
}

func (s *SecurityTrustCert) getKeychain() string {
	keychain := "user"

	if s.keychain == KeychainSystem {
		keychain = "system"
	}

	cmd := exec.Command("security", "default-keychain", "-d", keychain)

	out, err := cmd.CombinedOutput()
	if err != nil {
		s.err = err
	}

	s.keychainPath = strings.Trim(strings.TrimSpace(string(out)), `"`)

	return s.keychainPath
}

func (s *SecurityTrustCert) setResultType(st string) *SecurityTrustCert {
	s.resultType = st
	return s
}

func (s *SecurityTrustCert) getResultType() string {
	if s.resultType == "" {
		s.resultType = "trustRoot"
	}

	return s.resultType
}

func (s *SecurityTrustCert) getPolicy() string {
	if s.policy == "" {
		s.policy = "ssl"
	}

	return s.policy
}

func (s *SecurityTrustCert) setCertPath(cp string) {
	s.certPath = cp
}

func (s *SecurityTrustCert) AddTrustedCert(certPath ...string) error {
	if s.err != nil {
		return s.err
	}

	if len(certPath) == 1 {
		s.setCertPath(certPath[0])
	}

	// appPath := ""
	// if s.appPath != "" {
	// 	appPath = fmt.Sprintf("-a %s", s.appPath)
	// }

	// policyString := ""
	// if s.policyString != "" {
	// 	policyString = fmt.Sprintf("-s %s", s.policyString)
	// }

	// allowedError := ""
	// if s.allowedError != "" {
	// 	allowedError = fmt.Sprintf("-e %s", s.allowedError)
	// }

	// keyUsage := ""
	// if s.keyUsage != 0 {
	// 	keyUsage = fmt.Sprintf("-u %d", s.keyUsage)
	// }

	// settingsFileIn := ""
	// if s.settingsFileIn != "" {
	// 	settingsFileIn = fmt.Sprintf("-i %s", s.settingsFileIn)
	// }

	// settingsFileOut := ""
	// if s.settingsFileOut != "" {
	// 	settingsFileOut = fmt.Sprintf("-o %s", s.settingsFileOut)
	// }

	cmd := exec.Command("security",
		"add-trusted-cert",
		"-d",
		"-r", s.getResultType(),
		"-p", s.getPolicy(),
		"-k", s.getKeychain(),
		s.certPath,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		s.err = errors.New(string(out))
		return s.err
	}

	return nil
}

func (s *SecurityTrustCert) RemoveTrustedCert() error {
	certPEMBlock, err := os.ReadFile(s.certPath)
	if err != nil {
		return err
	}

	certDERBlock, _ := pem.Decode(certPEMBlock)

	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return err
	}

	cmd := exec.Command("security",
		"remove-trusted-cert",
		"-d",
		s.certPath,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("%s", out)
	}

	cmd = exec.Command("security",
		"delete-certificate",
		"-c", x509Cert.Subject.CommonName,
		s.getKeychain())

	out, err = cmd.CombinedOutput()
	if err != nil {
		s.err = errors.New(string(out))
		return s.err
	}
	return s.err
}
