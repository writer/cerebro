package cloudidentitysource

import "fmt"

// ErrArchiveEntryBoundExceeded is returned when a tar/tar.gz archive
// (a fetched Helm chart package or a whole-repository archive download)
// contains more header entries -- of any type, including directories and
// other non-regular headers that still cost full header parsing and gzip
// decompression work -- than the caller-configured bound allows. It is a
// resource-exhaustion guard, not a content-validity check: callers
// distinguish it from other extraction failures via errors.As rather than
// matching on message text.
type ErrArchiveEntryBoundExceeded struct {
	Limit int
}

func (e *ErrArchiveEntryBoundExceeded) Error() string {
	return fmt.Sprintf("archive exceeded the %d entry bound", e.Limit)
}

// ErrArchiveAggregateBoundExceeded is returned when the total decompressed
// bytes read from a tar/tar.gz archive, summed across every entry (wanted
// or not, extracted or merely drained to advance the reader), exceeds the
// caller-configured aggregate bound. A highly compressible archive within a
// bounded compressed download size could otherwise still expand toward an
// unbounded multiple of it via many individually sub-per-entry-limit
// entries; this bound stops that independent of any single entry's size.
type ErrArchiveAggregateBoundExceeded struct {
	Limit int64
}

func (e *ErrArchiveAggregateBoundExceeded) Error() string {
	return fmt.Sprintf("archive exceeded the %d aggregate decompressed byte bound", e.Limit)
}
