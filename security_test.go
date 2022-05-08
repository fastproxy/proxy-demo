package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetKeychain(t *testing.T) {
	s := NewSecurityTrustCert()

	s.getKeychain()

	if s.err != nil {
		t.Error(s.err)
	}

	if !strings.HasSuffix(s.keychainPath, `login.keychain-db"`) {
		t.Errorf("Expected login keychain, got %s", s.keychainPath)
	} else {
		t.Logf(s.keychainPath)
	}

	s.setKeychainType(KeychainSystem)
	s.getKeychain()

	if !strings.HasSuffix(s.keychainPath, `System.keychain"`) {
		t.Errorf("Expected login keychain, got %s", s.keychainPath)
	} else {
		t.Logf(s.keychainPath)
	}
}

func TestAddTrustedCert(t *testing.T) {
	s := NewSecurityTrustCert()

	abs, _ := filepath.Abs("./cert/root.cert.pem")
	err := s.AddTrustedCert(abs)
	if err != nil {
		t.Error(err)
	} else if s.err != nil {
		t.Error(s.err)
	}
	t.Logf("add done")
	time.Sleep(time.Second * 5)
	err = s.RemoveTrustedCert()
	if err != nil {
		t.Error(err)
	} else if s.err != nil {
		t.Error(s.err)
	}
}
