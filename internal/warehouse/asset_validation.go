package warehouse

import (
	"strings"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/snowflake"
)

func normalizeAssetTableName(table string) (string, error) {
	table = strings.ToLower(strings.TrimSpace(table))
	if err := snowflake.ValidateTableNameStrict(table); err != nil {
		return "", cerrors.E(cerrors.Op("warehouse.normalize_asset_table"), cerrors.ErrInvalidInput, err)
	}
	return table, nil
}
