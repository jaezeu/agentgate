package main

import "testing"

func TestVersionCommand(t *testing.T) {
	t.Parallel()
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version command: %v", err)
	}
	if err := run([]string{"version", "extra"}); err == nil {
		t.Fatal("version command accepted an argument")
	}
}
