package sourcecdk

import (
	"fmt"
	"strconv"
	"strings"
)

// PageByOffset returns the window of items addressed by a decimal offset cursor
// together with the cursor for the following page. An empty cursor starts at
// the beginning of items; the returned next cursor is empty once items are
// exhausted. It lets sources that buffer a full result set page over it with a
// stable, opaque integer cursor without reimplementing the bounds arithmetic.
func PageByOffset[T any](items []T, cursor string, pageSize int) ([]T, string, error) {
	offset := 0
	if strings.TrimSpace(cursor) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(cursor))
		if err != nil || parsed < 0 {
			return nil, "", fmt.Errorf("invalid offset cursor %q", cursor)
		}
		offset = parsed
	}
	if offset >= len(items) {
		return nil, "", nil
	}
	end := offset + pageSize
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[offset:end], next, nil
}
