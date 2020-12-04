package collector_test

import (
	"github.com/fluepke/vodafone-station-exporter/collector"
	"testing"
)

func TestDoPbkdf2NotCoded(t *testing.T) {
	result := collector.DoPbkdf2NotCoded("EqAM2KtT", "2awfm2st3cej")
	if result != "c2523cb6738663f9d9223c905c59cbb6" {
		t.Errorf("Got %s", result)
	}
}

func TestGetLoginPassword(t *testing.T) {
	loginPassword := collector.GetLoginPassword("EqAM2KtT", "2awfm2st3cej", "4hbeVQ1Z6HK2")
	if loginPassword != "b000b59875d1dc81bcd9d8f658fc7e77" {
		t.Errorf("Derivation of login password failed!")
	}
}
