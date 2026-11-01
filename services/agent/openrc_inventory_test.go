package main

import (
	"reflect"
	"testing"
)

func TestOpenRCServiceInventoryParsesUnprivilegedMachineOutput(t *testing.T) {
	output := &cappedOutput{b: []byte("sshd =  started \nselfguard-collector = started 00:01:48 (0)\ncrond = stopped\nbroken = crashed\npending = scheduled\n")}
	rows, status := openRCServiceLines(output)
	want := []Service{{"sshd", "active"}, {"selfguard-collector", "active"}, {"crond", "inactive"}, {"broken", "failed"}, {"pending", "activating"}}
	if !status.Complete || !reflect.DeepEqual(rows, want) {
		t.Fatal(rows, status)
	}
}

func TestOpenRCServiceInventoryKeepsInvalidOrTruncatedOutputIncomplete(t *testing.T) {
	for _, text := range []string{"", "not a service row\n", "sshd = imaginary\n", "--help = started\n", "sshd = started\nsshd = stopped\n"} {
		if _, status := openRCServiceLines(&cappedOutput{b: []byte(text)}); status.Complete {
			t.Fatalf("invalid output declared complete: %q", text)
		}
	}
	if _, status := openRCServiceLines(&cappedOutput{b: []byte("sshd = started\n"), truncated: true}); status.Complete {
		t.Fatal("truncated output declared complete")
	}
}
