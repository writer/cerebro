package runtime

func CloneStringMap(input map[string]string) map[string]string {
	return cloneRuntimeStringMap(input)
}

func FirstNonEmpty(values ...string) string {
	return firstNonEmptyRuntime(values...)
}
