package collector_test

import (
	"github.com/fluepke/vodafone-station-exporter/collector"
	"testing"
)

func TestDoPbkdf2NotCoded(t *testing.T) {
	result := collector.DoPbkdf2NotCoded("passw0rd", "s4lt")
	if result != "22995aae586afda236e436c7df61860a" {
		t.Errorf("DoPbkdf2NotCoded failed")
	}
}

func TestGetLoginPassword(t *testing.T) {
	loginPassword := collector.GetLoginPassword("passw0rd", "s4lt", "s4ltWebUi")
	if loginPassword != "73446f649cc5fa67d05f76c1048e3140" {
		t.Errorf("Derivation of login password failed")
	}
}
