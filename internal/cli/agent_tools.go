package cli

import (
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/snowflake"
)

func agentToolsSnowflakeClient(application *app.App) *snowflake.Client {
	if application == nil {
		return nil
	}
	if application.Snowflake != nil {
		return application.Snowflake
	}
	return application.LegacySnowflake
}
