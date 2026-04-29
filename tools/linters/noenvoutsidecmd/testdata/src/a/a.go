package a

import "os"

func Bad() string {
	return os.Getenv("HOME") // want `os.Getenv is forbidden outside cmd/ and config`
}

func AlsoBad() (string, bool) {
	value, ok := os.LookupEnv("HOME") // want `os.LookupEnv is forbidden outside cmd/ and config`
	return value, ok
}
