package a

import (
	"context"
	. "context"
	c "context"
)

func Bad() context.Context {
	return context.Background() // want `context.Background is forbidden outside cmd/ and tests`
}

func AlsoBad() context.Context {
	return context.TODO() // want `context.TODO is forbidden outside cmd/ and tests`
}

func AliasBad() context.Context {
	return c.Background() // want `context.Background is forbidden outside cmd/ and tests`
}

func DotBad() context.Context {
	return TODO() // want `context.TODO is forbidden outside cmd/ and tests`
}

func FuncValueBad() context.Context {
	background := context.Background
	return background() // want `context.Background is forbidden outside cmd/ and tests`
}

func FuncValueAliasBad() context.Context {
	todo := c.TODO
	return todo() // want `context.TODO is forbidden outside cmd/ and tests`
}
