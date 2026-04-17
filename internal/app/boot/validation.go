package boot

import (
	"fmt"
	"sort"
	"strings"
)

func RunInitStep(name string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	if fn != nil {
		fn()
	}
	return nil
}

func RunInitErrorStep(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

func ValidateRequiredServices(required map[string]bool) error {
	var missing []string
	for service, initialized := range required {
		if initialized {
			continue
		}
		missing = append(missing, service)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("required services not initialized: %s", strings.Join(missing, ", "))
	}
	return nil
}
