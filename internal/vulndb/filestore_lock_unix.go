//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package vulndb

import (
	"os"
	"path/filepath"
	"syscall"
)

func (s *FileStore) lockStateFile() (func(), error) {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(lock.Fd()) // #nosec G115 -- file descriptors fit in int on supported Unix platforms.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}
