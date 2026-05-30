package sourceprojection

import "testing"

func TestCanonicalProjectedEntityType(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: "aws.aws.iam.policy", want: "aws.iam.policy"},
		{input: "okta.publicclientappentity", want: "okta.publicclientapp"},
		{input: "okta.ip address", want: "okta.ip"},
		{input: "github.code.repository", want: "github.code.repository"},
	}
	for _, tc := range cases {
		if got := canonicalProjectedEntityType(tc.input); got != tc.want {
			t.Fatalf("canonicalProjectedEntityType(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
