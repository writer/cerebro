package gcpcloud

import "strings"

// CollectPages follows page tokens until the provider returns no next token.
func CollectPages[T any](fetch func(pageToken string) ([]T, string, error)) ([]T, error) {
	records := make([]T, 0)
	pageToken := ""
	for {
		page, next, err := fetch(pageToken)
		if err != nil {
			return nil, err
		}
		records = append(records, page...)
		if strings.TrimSpace(next) == "" {
			return records, nil
		}
		pageToken = next
	}
}
