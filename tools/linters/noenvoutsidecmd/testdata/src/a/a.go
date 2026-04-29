package a

import (
	"os"
	. "os"
	o "os"
)

func Bad() string {
	return os.Getenv("HOME") // want `os.Getenv is forbidden outside cmd/ and config`
}

func AlsoBad() (string, bool) {
	value, ok := os.LookupEnv("HOME") // want `os.LookupEnv is forbidden outside cmd/ and config`
	return value, ok
}

func AliasBad() string {
	return o.Getenv("HOME") // want `os.Getenv is forbidden outside cmd/ and config`
}

func DotBad() (string, bool) {
	return LookupEnv("HOME") // want `os.LookupEnv is forbidden outside cmd/ and config`
}

func FuncValueBad() string {
	get := os.Getenv
	return get("HOME") // want `os.Getenv is forbidden outside cmd/ and config`
}

func FuncValueAliasBad() (string, bool) {
	lookup := o.LookupEnv
	return lookup("HOME") // want `os.LookupEnv is forbidden outside cmd/ and config`
}
