//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package vulndb

import "fmt"

func (s *FileStore) lockStateFile() (func(), error) {
	return nil, fmt.Errorf("vulndb file store locking is unsupported on this platform")
}
