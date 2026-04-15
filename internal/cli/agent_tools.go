package cli

import (
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/warehouse"
)

func agentToolsSnowflakeClient(application *app.App) warehouse.DataWarehouse {
	if application == nil {
		return nil
	}
	if application.Warehouse != nil {
		return application.Warehouse
	}
	if application.Snowflake != nil {
		return application.Snowflake
	}
	return application.LegacySnowflake
}
