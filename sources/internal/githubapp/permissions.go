package githubapp

import (
	"reflect"
	"sort"
	"strings"

	gogithub "github.com/google/go-github/v66/github"
)

// InstallationPermissionPairs returns stable policy evidence values such as contents:read.
func InstallationPermissionPairs(permissions *gogithub.InstallationPermissions) []string {
	if permissions == nil {
		return nil
	}
	value := reflect.ValueOf(permissions).Elem()
	valueType := value.Type()
	result := make([]string, 0, value.NumField())
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() != reflect.Ptr || field.IsNil() || field.Elem().Kind() != reflect.String {
			continue
		}
		name := strings.TrimSpace(strings.Split(valueType.Field(i).Tag.Get("json"), ",")[0])
		access := strings.TrimSpace(field.Elem().String())
		if name == "" || name == "-" || access == "" {
			continue
		}
		result = append(result, name+":"+access)
	}
	sort.Strings(result)
	return result
}
