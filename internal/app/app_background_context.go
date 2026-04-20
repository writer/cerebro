package app

import "context"

func (a *App) backgroundContext() context.Context {
	if a != nil {
		if a.rootCtx != nil {
			return backgroundWorkContext(a.rootCtx)
		}
		if a.graphCtx != nil {
			return backgroundWorkContext(a.graphCtx)
		}
	}
	return context.Background()
}
