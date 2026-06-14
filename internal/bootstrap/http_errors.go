package bootstrap

import (
	"net/http"
	"strings"
)

func safeHTTPErrorMessage(status int, err error) string {
	if status >= http.StatusInternalServerError {
		message := strings.ToLower(http.StatusText(status))
		if message == "" {
			return "internal server error"
		}
		return message
	}
	if err == nil {
		return strings.ToLower(http.StatusText(status))
	}
	return err.Error()
}
