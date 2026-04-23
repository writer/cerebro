package main

import "os"

func ReadEnv() (string, bool) {
	value, ok := os.LookupEnv("HOME")
	return value, ok
}
