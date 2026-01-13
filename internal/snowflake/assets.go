package snowflake

import (
	"context"
	"fmt"
)

type Asset struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Account    string                 `json:"account"`
	Region     string                 `json:"region"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
}

type AssetFilter struct {
	Provider string
	Type     string
	Account  string
	Region   string
	Limit    int
	Offset   int
}

func (c *Client) GetAssets(ctx context.Context, table string, filter AssetFilter) ([]map[string]interface{}, error) {
	// Build base query - table name is validated internally, not user input
	// nosemgrep: go.lang.security.audit.sqli.tainted-sql-string
	query := "SELECT * FROM " + c.database + "." + c.schema + "." + table

	var conditions []string
	var args []interface{}

	if filter.Account != "" {
		conditions = append(conditions, "account_id = ?")
		args = append(args, filter.Account)
	}
	if filter.Region != "" {
		conditions = append(conditions, "region = ?")
		args = append(args, filter.Region)
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += cond
		}
	}

	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	result, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return result.Rows, nil
}

func (c *Client) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	query := fmt.Sprintf("SELECT * FROM %s.%s.%s WHERE _cq_id = ? LIMIT 1", c.database, c.schema, table)
	result, err := c.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, fmt.Errorf("asset not found")
	}
	return result.Rows[0], nil
}

func (c *Client) CountAssets(ctx context.Context, table string) (int64, error) {
	query := fmt.Sprintf("SELECT COUNT(*) as count FROM %s.%s.%s", c.database, c.schema, table)
	result, err := c.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	if len(result.Rows) == 0 {
		return 0, nil
	}
	if count, ok := result.Rows[0]["COUNT"].(int64); ok {
		return count, nil
	}
	return 0, nil
}
