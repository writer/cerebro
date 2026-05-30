package bodyread

import (
	"strconv"
	"strings"
	"testing"
)

func TestFindUnboundedReadAllAdversarialFixtures(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "direct unbounded read",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	_, _ = io.ReadAll(resp.Body())
}`,
			want: 1,
		},
		{
			name: "direct limit reader",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	_, _ = io.ReadAll(io.LimitReader(resp.Body(), 1024))
}`,
			want: 0,
		},
		{
			name: "aliased io import",
			code: `package fixture
import stdio "io"
func f(resp interface{ Body() stdio.Reader }) {
	_, _ = stdio.ReadAll(stdio.LimitReader(resp.Body(), 1024))
}`,
			want: 0,
		},
		{
			name: "local io value is ignored",
			code: `package fixture
type localIO struct{}
func (localIO) ReadAll(any) ([]byte, error) { return nil, nil }
func f(body any) {
	io := localIO{}
	_, _ = io.ReadAll(body)
}`,
			want: 0,
		},
		{
			name: "multiline limit reader",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	limited := io.LimitReader(
		resp.Body(),
		1024,
	)
	_, _ = io.ReadAll(limited)
}`,
			want: 0,
		},
		{
			name: "comments and strings are ignored",
			code: `package fixture
func f() {
	_ = "io.ReadAll(resp.Body)"
	// io.ReadAll(resp.Body)
}`,
			want: 0,
		},
		{
			name: "shadowed reader is unsafe",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	reader := io.LimitReader(resp.Body(), 1024)
	{
		reader := resp.Body()
		_, _ = io.ReadAll(reader)
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "if initializer does not leak",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ok bool) {
	if reader := io.LimitReader(resp.Body(), 1024); ok {
		_, _ = io.ReadAll(reader)
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "if body reassignment escapes",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ok bool) {
	reader := io.LimitReader(resp.Body(), 1024)
	if ok {
		reader = resp.Body()
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "both if branches keep reader bounded",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ok bool) {
	reader := resp.Body()
	if ok {
		reader = io.LimitReader(resp.Body(), 1024)
	} else {
		reader = io.LimitReader(resp.Body(), 2048)
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 0,
		},
		{
			name: "bare block reassignment escapes",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	reader := io.LimitReader(resp.Body(), 1024)
	{
		reader = resp.Body()
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "switch break continues after switch",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, n int) {
	reader := io.LimitReader(resp.Body(), 1024)
	switch n {
	case 1:
		reader = resp.Body()
		break
	default:
		return
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "switch fallthrough carries state",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, n int) {
	reader := io.LimitReader(resp.Body(), 1024)
	switch n {
	case 1:
		reader = resp.Body()
		fallthrough
	case 2:
		_, _ = io.ReadAll(reader)
	}
}`,
			want: 1,
		},
		{
			name: "select case mutation escapes",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ch <-chan struct{}) {
	reader := io.LimitReader(resp.Body(), 1024)
	select {
	case <-ch:
		reader = resp.Body()
	default:
		return
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "immediate function literal mutation is modeled",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	reader := io.LimitReader(resp.Body(), 1024)
	func() {
		reader = resp.Body()
	}()
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "non executed function literal is ignored",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	reader := io.LimitReader(resp.Body(), 1024)
	_ = func() {
		reader = resp.Body()
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 0,
		},
		{
			name: "labeled statement mutation is modeled",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }) {
	reader := io.LimitReader(resp.Body(), 1024)
raw:
	{
		reader = resp.Body()
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "loop mutation is conservative",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ok bool) {
	reader := io.LimitReader(resp.Body(), 1024)
	for ok {
		reader = resp.Body()
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "range body may not execute",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, values []string) {
	reader := resp.Body()
	for range values {
		reader = io.LimitReader(resp.Body(), 1024)
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 1,
		},
		{
			name: "range keeps reader bounded when already bounded",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, values []string) {
	reader := io.LimitReader(resp.Body(), 1024)
	for range values {
		reader = io.LimitReader(resp.Body(), 2048)
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 0,
		},
		{
			name: "early return keeps unsafe branch from escaping",
			code: `package fixture
import "io"
func f(resp interface{ Body() io.Reader }, ok bool) {
	reader := io.LimitReader(resp.Body(), 1024)
	if ok {
		reader = resp.Body()
		return
	}
	_, _ = io.ReadAll(reader)
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := FindUnboundedReadAll("fixture.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("FindUnboundedReadAll: %v", err)
			}
			if len(findings) != tt.want {
				t.Fatalf("findings = %d (%s), want %d", len(findings), formatFindings(findings), tt.want)
			}
		})
	}
}

func formatFindings(findings []Finding) string {
	var parts []string
	for _, finding := range findings {
		parts = append(parts, finding.File+":"+strconv.Itoa(finding.Line))
	}
	return strings.Join(parts, ", ")
}
