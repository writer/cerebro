package grcupload

import (
	"context"
	"io"
)

type Parser interface {
	Parse(ctx context.Context, fileName string, contentType string, contents io.Reader) (ParsedDocument, error)
}
