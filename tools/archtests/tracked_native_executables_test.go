package archtests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryDoesNotTrackNativeExecutables(t *testing.T) {
	root := repoRoot(t)
	command := exec.Command("git", "ls-files", "-z")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list tracked files: %v", err)
	}

	var nativeExecutables []string
	for _, trackedPath := range bytes.Split(output, []byte{0}) {
		if len(trackedPath) == 0 {
			continue
		}
		name := string(trackedPath)
		contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read tracked file %q: %v", name, err)
		}
		if isNativeExecutable(contents) {
			nativeExecutables = append(nativeExecutables, name)
		}
	}

	if len(nativeExecutables) != 0 {
		t.Fatalf(
			"repository tracks native executable artifacts; build them from source instead:\n- %s",
			strings.Join(nativeExecutables, "\n- "),
		)
	}
}

func isNativeExecutable(contents []byte) bool {
	if len(contents) >= 4 {
		magic := contents[:4]
		for _, nativeMagic := range [][]byte{
			{0x7f, 'E', 'L', 'F'},
			{0xbe, 0xba, 0xfe, 0xca},
			{0xbf, 0xba, 0xfe, 0xca},
			{0xca, 0xfe, 0xba, 0xbe},
			{0xca, 0xfe, 0xba, 0xbf},
			{0xce, 0xfa, 0xed, 0xfe},
			{0xcf, 0xfa, 0xed, 0xfe},
			{0xfe, 0xed, 0xfa, 0xce},
			{0xfe, 0xed, 0xfa, 0xcf},
		} {
			if bytes.Equal(magic, nativeMagic) {
				return true
			}
		}
	}
	if len(contents) >= 64 && bytes.Equal(contents[:2], []byte{'M', 'Z'}) {
		headerOffset := int(contents[0x3c]) | int(contents[0x3d])<<8 |
			int(contents[0x3e])<<16 | int(contents[0x3f])<<24
		return headerOffset >= 0 && headerOffset+4 <= len(contents) &&
			bytes.Equal(contents[headerOffset:headerOffset+4], []byte{'P', 'E', 0, 0})
	}
	return false
}

func TestNativeExecutableMagic(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
		want     bool
	}{
		{name: "shell script", contents: []byte("#!/bin/sh\nexit 0\n")},
		{name: "ELF", contents: []byte{0x7f, 'E', 'L', 'F'}, want: true},
		{name: "universal Mach-O", contents: []byte{0xca, 0xfe, 0xba, 0xbe}, want: true},
		{name: "byte-swapped universal Mach-O", contents: []byte{0xbe, 0xba, 0xfe, 0xca}, want: true},
		{name: "little-endian 64-bit Mach-O", contents: []byte{0xcf, 0xfa, 0xed, 0xfe}, want: true},
		{name: "short DOS marker", contents: []byte{'M', 'Z'}},
		{
			name: "PE",
			contents: append(
				append([]byte{'M', 'Z'}, make([]byte, 58)...),
				[]byte{64, 0, 0, 0, 'P', 'E', 0, 0}...,
			),
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isNativeExecutable(test.contents); got != test.want {
				t.Fatalf("isNativeExecutable() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAgentReceiptHookIsBuiltFromSourceInCI(t *testing.T) {
	root := repoRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "agent-receipt-hook.yml"))
	if err != nil {
		t.Fatalf("read agent receipt hook workflow: %v", err)
	}
	runner, err := os.ReadFile(
		filepath.Join(root, "plugins", "cerebro-agent-receipts", "scripts", "run-hook.sh"),
	)
	if err != nil {
		t.Fatalf("read agent receipt hook runner: %v", err)
	}

	workflowText := string(workflow)
	for _, marker := range []string{
		"plugins/cerebro-agent-receipts/**",
		"runs-on: macos-15-intel",
		"swift run",
		"ReceiptCoreChecks",
		"script/build_hook_release.sh",
		"lipo -verify_arch arm64 x86_64",
		"codesign --verify --strict",
		"shasum -a 256",
		"actions/upload-artifact@",
	} {
		if !strings.Contains(workflowText, marker) {
			t.Errorf("agent receipt hook workflow missing %q", marker)
		}
	}
	runnerText := string(runner)
	if strings.Contains(runnerText, "BUNDLED_BINARY") {
		t.Error("agent receipt hook runner must not execute a repository-bundled binary")
	}
	for _, marker := range []string{"INSTALLED_BINARY", "swift build", "codesign --verify --strict"} {
		if !strings.Contains(runnerText, marker) {
			t.Errorf("agent receipt hook runner missing %q", marker)
		}
	}
}
