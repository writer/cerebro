package sourcecdk

import "testing"

func TestPageByOffset(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	cases := []struct {
		name     string
		cursor   string
		pageSize int
		want     []string
		wantNext string
		wantErr  bool
	}{
		{name: "first page", cursor: "", pageSize: 2, want: []string{"a", "b"}, wantNext: "2"},
		{name: "middle page", cursor: "2", pageSize: 2, want: []string{"c", "d"}, wantNext: "4"},
		{name: "final partial page", cursor: "4", pageSize: 2, want: []string{"e"}, wantNext: ""},
		{name: "offset at end", cursor: "5", pageSize: 2, want: nil, wantNext: ""},
		{name: "offset past end", cursor: "9", pageSize: 2, want: nil, wantNext: ""},
		{name: "page larger than items", cursor: "", pageSize: 10, want: []string{"a", "b", "c", "d", "e"}, wantNext: ""},
		{name: "whitespace cursor starts at zero", cursor: "  ", pageSize: 2, want: []string{"a", "b"}, wantNext: "2"},
		{name: "non-numeric cursor", cursor: "abc", pageSize: 2, wantErr: true},
		{name: "negative cursor", cursor: "-1", pageSize: 2, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, next, err := PageByOffset(items, tc.cursor, tc.pageSize)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("PageByOffset() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("PageByOffset() error = %v", err)
			}
			if next != tc.wantNext {
				t.Fatalf("next cursor = %q, want %q", next, tc.wantNext)
			}
			if len(page) != len(tc.want) {
				t.Fatalf("page = %v, want %v", page, tc.want)
			}
			for i := range page {
				if page[i] != tc.want[i] {
					t.Fatalf("page[%d] = %q, want %q", i, page[i], tc.want[i])
				}
			}
		})
	}
}
