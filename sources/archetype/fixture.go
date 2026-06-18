package archetype

import "github.com/writer/cerebro/internal/sourcecdk"

// NewFixture constructs the Archetype source used by integration tests.
func NewFixture() (sourcecdk.Source, error) {
	source, err := New()
	if err != nil {
		return nil, err
	}
	source.allowLoopbackBaseURL = true
	return source, nil
}
