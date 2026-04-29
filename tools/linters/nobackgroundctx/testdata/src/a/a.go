package a

import "context"

func Bad() context.Context {
	return context.Background() // want `context.Background is forbidden outside cmd/ and tests`
}

func AlsoBad() context.Context {
	return context.TODO() // want `context.TODO is forbidden outside cmd/ and tests`
}
