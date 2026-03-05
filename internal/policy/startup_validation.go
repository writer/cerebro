package policy

import (
	"errors"
	"fmt"
	"sync"

	nativesync "github.com/writer/cerebro/internal/sync"
)

var (
	startupValidationOnce sync.Once
	startupValidationErr  error
)

// ValidateStartupMappings validates mapping and table registry consistency.
func ValidateStartupMappings() error {
	startupValidationOnce.Do(func() {
		registry := GlobalMappingRegistry()
		var errs []error
		errs = append(errs, registry.Validate()...)
		errs = append(errs, registry.ValidateNativeTableMappings(nativesync.SupportedTableNames())...)
		if len(errs) > 0 {
			startupValidationErr = errors.Join(errs...)
		}
	})

	return startupValidationErr
}

// MustValidateStartupMappings panics when startup validation fails.
func MustValidateStartupMappings() {
	if err := ValidateStartupMappings(); err != nil {
		panic(fmt.Sprintf("policy startup mapping validation failed: %v", err))
	}
}
