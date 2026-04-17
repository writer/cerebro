package findings

type resolveWithErrorStore interface {
	ResolveWithError(id string) error
}

type resolver interface {
	Resolve(id string) bool
}

type suppressWithErrorStore interface {
	SuppressWithError(id string) error
}

type suppressor interface {
	Suppress(id string) bool
}

func ResolveStore(store resolver, id string) error {
	if store == nil {
		return ErrIssueNotFound
	}
	if resolver, ok := store.(resolveWithErrorStore); ok {
		return resolver.ResolveWithError(id)
	}
	if store.Resolve(id) {
		return nil
	}
	return ErrIssueNotFound
}

func SuppressStore(store suppressor, id string) error {
	if store == nil {
		return ErrIssueNotFound
	}
	if suppressor, ok := store.(suppressWithErrorStore); ok {
		return suppressor.SuppressWithError(id)
	}
	if store.Suppress(id) {
		return nil
	}
	return ErrIssueNotFound
}
