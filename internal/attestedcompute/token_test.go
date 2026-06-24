package attestedcompute

import "testing"

func TestTokenizerDeterministicAndDomainSeparated(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tokenizer, err := NewTokenizer(key)
	if err != nil {
		t.Fatalf("NewTokenizer() error = %v", err)
	}
	emailA := tokenizer.Token("identity.email", "alice@example.com")
	emailB := tokenizer.Token("identity.email", "alice@example.com")
	login := tokenizer.Token("identity.login", "alice@example.com")
	if emailA == "" || emailA != emailB {
		t.Fatalf("Token() not deterministic: %q vs %q", emailA, emailB)
	}
	if emailA == login {
		t.Fatalf("Token() must be domain separated")
	}
	if !TokenLike(emailA) {
		t.Fatalf("TokenLike(%q) = false, want true", emailA)
	}
	if got := TokenURN("tenant", "okta.user", emailA); got != "urn:cerebro:tenant:attested:okta.user:"+emailA {
		t.Fatalf("TokenURN() = %q", got)
	}
}

func TestNewTokenizerRejectsShortKey(t *testing.T) {
	if _, err := NewTokenizer([]byte("short")); err == nil {
		t.Fatalf("NewTokenizer() error = nil, want error")
	}
}
