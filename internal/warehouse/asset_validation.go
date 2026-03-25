package warehouse

import (
	"strings"

	"github.com/writer/cerebro/internal/cerrors"
)

func normalizeAssetTableName(table string) (string, error) {
	table = strings.ToLower(strings.TrimSpace(table))
	if err := ValidateTableNameStrict(table); err != nil {
		return "", cerrors.E(cerrors.Op("warehouse.normalize_asset_table"), cerrors.ErrInvalidInput, err)
	}
	return table, nil
}
