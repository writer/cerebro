package github

import (
	"strings"

	gogithub "github.com/google/go-github/v66/github"
)

func githubUserLogin(user *gogithub.User) string {
	if user == nil {
		return ""
	}
	return strings.TrimSpace(user.GetLogin())
}

func githubUserID(user *gogithub.User) int64 {
	if user == nil {
		return 0
	}
	return user.GetID()
}
