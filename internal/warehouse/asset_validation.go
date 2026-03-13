package warehouse

import (
	"strings"

	"github.com/evalops/cerebro/internal/cerrors"
	"github.com/evalops/cerebro/internal/snowflake"
)

func normalizeAssetTableName(table string) (string, error) {
	table = strings.ToLower(strings.TrimSpace(table))
	if err := snowflake.ValidateTableNameStrict(table); err != nil {
		return "", cerrors.E(cerrors.Op("warehouse.normalize_asset_table"), cerrors.ErrInvalidInput, err)
	}
	return table, nil
}
