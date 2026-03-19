package app

import "time"

const (
	defaultAPIRequestTimeout                      = 60 * time.Second
	defaultAPIMaxBodyBytes                  int64 = 10 * 1024 * 1024
	defaultShutdownTimeout                        = 30 * time.Second
	defaultHealthCheckTimeout                     = 5 * time.Second
	defaultGraphRiskEngineStateTimeout            = 2 * time.Second
	defaultThreatIntelSyncTimeout                 = 2 * time.Minute
	defaultThreatIntelSyncMaxAge                  = 12 * time.Hour
	defaultThreatIntelSyncAttempts                = 3
	defaultThreatIntelSyncBackoff                 = 5 * time.Second
	defaultTicketingProviderValidateTimeout       = 5 * time.Second
	defaultGraphConsistencyCheckTimeout           = 30 * time.Minute
)

func (c *Config) APIRequestTimeoutOrDefault() time.Duration {
	if c == nil || c.APIRequestTimeout <= 0 {
		return defaultAPIRequestTimeout
	}
	return c.APIRequestTimeout
}

func (c *Config) APIMaxBodyBytesOrDefault() int64 {
	if c == nil || c.APIMaxBodyBytes <= 0 {
		return defaultAPIMaxBodyBytes
	}
	return c.APIMaxBodyBytes
}

func (c *Config) ShutdownTimeoutOrDefault() time.Duration {
	if c == nil || c.ShutdownTimeout <= 0 {
		return defaultShutdownTimeout
	}
	return c.ShutdownTimeout
}

func (c *Config) HealthCheckTimeoutOrDefault() time.Duration {
	if c == nil || c.HealthCheckTimeout <= 0 {
		return defaultHealthCheckTimeout
	}
	return c.HealthCheckTimeout
}

func (c *Config) GraphRiskEngineStateTimeoutOrDefault() time.Duration {
	if c == nil || c.GraphRiskEngineStateTimeout <= 0 {
		return defaultGraphRiskEngineStateTimeout
	}
	return c.GraphRiskEngineStateTimeout
}

func (c *Config) ThreatIntelSyncTimeoutOrDefault() time.Duration {
	if c == nil || c.ThreatIntelSyncTimeout <= 0 {
		return defaultThreatIntelSyncTimeout
	}
	return c.ThreatIntelSyncTimeout
}

func (c *Config) ThreatIntelSyncMaxAgeOrDefault() time.Duration {
	if c == nil || c.ThreatIntelSyncMaxAge <= 0 {
		return defaultThreatIntelSyncMaxAge
	}
	return c.ThreatIntelSyncMaxAge
}

func (c *Config) ThreatIntelSyncAttemptsOrDefault() int {
	if c == nil || c.ThreatIntelSyncAttempts <= 0 {
		return defaultThreatIntelSyncAttempts
	}
	return c.ThreatIntelSyncAttempts
}

func (c *Config) ThreatIntelSyncBackoffOrDefault() time.Duration {
	if c == nil || c.ThreatIntelSyncBackoff <= 0 {
		return defaultThreatIntelSyncBackoff
	}
	return c.ThreatIntelSyncBackoff
}

func (c *Config) TicketingProviderValidateTimeoutOrDefault() time.Duration {
	if c == nil || c.TicketingProviderValidateTimeout <= 0 {
		return defaultTicketingProviderValidateTimeout
	}
	return c.TicketingProviderValidateTimeout
}

func (c *Config) GraphConsistencyCheckTimeoutOrDefault() time.Duration {
	if c == nil || c.GraphConsistencyCheckTimeout <= 0 {
		return defaultGraphConsistencyCheckTimeout
	}
	return c.GraphConsistencyCheckTimeout
}
