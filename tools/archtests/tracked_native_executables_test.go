package archtests

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// trackedEntry is one Git index entry the guard reads from the object store.
type trackedEntry struct {
	mode string
	sha  string
	path string
}

func TestRepositoryDoesNotTrackNativeExecutables(t *testing.T) {
	root := repoRoot(t)

	// Read each tracked path's content from the Git index (the staged
	// blob the next commit would contain), not from the working tree.
	// This both avoids false passes when a tracked file has been deleted
	// (staged or unstaged) on disk without being removed from the index,
	// and avoids any need to write to the working tree or index to check.
	command := exec.Command("git", "ls-files", "-s", "-z")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list tracked files: %v", err)
	}

	var entries []trackedEntry
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		// Format: "<mode> <sha> <stage>\t<path>"
		fields := strings.SplitN(string(record), "\t", 2)
		if len(fields) != 2 {
			t.Fatalf("unexpected git ls-files -s record: %q", record)
		}
		meta := strings.Fields(fields[0])
		if len(meta) != 3 {
			t.Fatalf("unexpected git ls-files -s metadata: %q", fields[0])
		}
		mode, sha, path := meta[0], meta[1], fields[1]
		// Gitlinks (submodules, mode 160000) are not blobs; there is
		// nothing in the object database to read their content from.
		if mode == "160000" {
			continue
		}
		entries = append(entries, trackedEntry{mode: mode, sha: sha, path: path})
	}

	batch := exec.Command("git", "cat-file", "--batch")
	batch.Dir = root
	stdin, err := batch.StdinPipe()
	if err != nil {
		t.Fatalf("open cat-file stdin: %v", err)
	}
	stdout, err := batch.StdoutPipe()
	if err != nil {
		t.Fatalf("open cat-file stdout: %v", err)
	}
	if err := batch.Start(); err != nil {
		t.Fatalf("start git cat-file --batch: %v", err)
	}
	requestErr := make(chan error, 1)
	go func() {
		requestErr <- writeCatFileRequests(stdin, entries)
	}()

	var nativeExecutables []string
	reader := bufio.NewReader(stdout)
	for _, entry := range entries {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read cat-file header for %q (%s): %v", entry.path, entry.sha, err)
		}
		header = strings.TrimSuffix(header, "\n")
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != entry.sha || fields[1] != "blob" {
			t.Fatalf("missing tracked blob %s for %q (git reported %q); a tracked path must always resolve to an object in the index", entry.sha, entry.path, header)
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("unparseable blob size for %q: %q", entry.path, header)
		}
		contents := make([]byte, size)
		if _, err := io.ReadFull(reader, contents); err != nil {
			t.Fatalf("read tracked blob content for %q: %v", entry.path, err)
		}
		if _, err := reader.ReadByte(); err != nil { // trailing newline after blob content
			t.Fatalf("read cat-file trailing newline for %q: %v", entry.path, err)
		}
		if isNativeExecutable(contents) {
			nativeExecutables = append(nativeExecutables, entry.path)
		}
	}
	if err := <-requestErr; err != nil {
		t.Fatalf("write git cat-file --batch requests: %v", err)
	}
	if err := batch.Wait(); err != nil {
		t.Fatalf("git cat-file --batch: %v", err)
	}

	if len(nativeExecutables) != 0 {
		t.Fatalf(
			"repository tracks native executable artifacts; build them from source instead:\n- %s",
			strings.Join(nativeExecutables, "\n- "),
		)
	}
}

// writeCatFileRequests streams one object request per tracked entry and
// closes the batch's stdin so git cat-file terminates; any write failure is
// returned so the guard fails closed rather than reading a short batch.
func writeCatFileRequests(stdin io.WriteCloser, entries []trackedEntry) error {
	writer := bufio.NewWriter(stdin)
	for _, entry := range entries {
		if _, err := fmt.Fprintln(writer, entry.sha); err != nil {
			_ = stdin.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = stdin.Close()
		return err
	}
	return stdin.Close()
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
		"lipo \"${helper}\" -verify_arch arm64 x86_64",
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
