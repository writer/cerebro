package coverageview

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/nhicoverage"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

type View string

const (
	Expanded View = "expanded"
	Summary  View = "summary"
	Page     View = "page"
)

var (
	ErrInvalidView   = errors.New("coverage_view must be summary or page when provided")
	errInvalidCursor = errors.New("cursor is invalid")
)

type PageMetadata struct {
	PageSize   int    `json:"page_size"`
	Returned   int    `json:"returned"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type PageResponse struct {
	nhicoverage.SourceCoverageResponse
	Page PageMetadata `json:"page"`
}

func FromRequest(r *http.Request) (View, error) {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("coverage_view"))) {
	case "":
		return Expanded, nil
	case string(Summary):
		return Summary, nil
	case string(Page):
		return Page, nil
	default:
		return Expanded, ErrInvalidView
	}
}

func Compact(response nhicoverage.SourceCoverageResponse) nhicoverage.SourceCoverageResponse {
	response.Records = nil
	response.BlindSpots = nil
	response.NHICoverage.Records = nil
	response.NHICoverage.BlindSpots = nil
	return response
}

func Paginate(r *http.Request, response nhicoverage.SourceCoverageResponse, records []sourcecoverage.Record) (PageResponse, error) {
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("blind_spots_only")), "true") {
		records = sourcecoverage.BlindSpots(records)
	}
	page, metadata, err := RecordsPage(r, records)
	if err != nil {
		return PageResponse{}, err
	}
	response.Records = page
	response.BlindSpots = nil
	response.NHICoverage.Records = nhicoverage.RecordsFromCoverage(page)
	response.NHICoverage.BlindSpots = nil
	return PageResponse{SourceCoverageResponse: response, Page: metadata}, nil
}

func RecordsPage(r *http.Request, records []sourcecoverage.Record) ([]sourcecoverage.Record, PageMetadata, error) {
	pageSize := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 500 {
			return nil, PageMetadata{}, errors.New("page_size must be between 1 and 500")
		}
		pageSize = parsed
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, PageMetadata{}, errInvalidCursor
		}
		parsed, err := strconv.Atoi(string(decoded))
		if err != nil || parsed < 0 {
			return nil, PageMetadata{}, errInvalidCursor
		}
		offset = parsed
	}
	if offset > len(records) {
		return nil, PageMetadata{}, errors.New("cursor is beyond the result set")
	}
	end := min(offset+pageSize, len(records))
	page := append([]sourcecoverage.Record(nil), records[offset:end]...)
	metadata := PageMetadata{PageSize: pageSize, Returned: len(page), Total: len(records)}
	if end < len(records) {
		metadata.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", end)))
	}
	return page, metadata, nil
}
