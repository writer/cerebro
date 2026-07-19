package eventadmission

import "errors"

// CloseOnError releases a closeable admitter when its owning construction fails.
func CloseOnError(admitter Admitter, target *error) {
	if target == nil || *target == nil {
		return
	}
	if closer, ok := admitter.(interface{ Close() error }); ok {
		*target = errors.Join(*target, closer.Close())
	}
}
