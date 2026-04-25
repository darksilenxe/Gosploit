package main

import "testing"

func TestValidateMetasploitFlagsRequiresSource(t *testing.T) {
	err := validateMetasploitFlags("", "", "", "", "", "", "execute", "", 0, repeatedValues{}, repeatedValues{}, false)
	if err == nil {
		t.Fatal("expected error when metasploit flags are used without metasploit module source")
	}
}

func TestValidateMetasploitFlagsRejectsMultipleSources(t *testing.T) {
	err := validateMetasploitFlags("exploit/web/sqlinjection", "", "", "", "", "/tmp/test.rc", "", "", 0, repeatedValues{}, repeatedValues{}, false)
	if err == nil {
		t.Fatal("expected source conflict error")
	}
}

func TestValidateMetasploitFlagsAcceptsMetasploitYAML(t *testing.T) {
	err := validateMetasploitFlags("", "", "", "", "/tmp/module.yaml", "", "simulate", "msfvenom", 15, repeatedValues{"rhost=1.1.1.1"}, repeatedValues{"--help"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
