package app

import "context"

type graphReplicaReplayContextKey struct{}

func withGraphReplicaReplay(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, graphReplicaReplayContextKey{}, true)
}

func withoutGraphReplicaReplay(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, graphReplicaReplayContextKey{}, false)
}

func graphReplicaReplayEnabled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(graphReplicaReplayContextKey{}).(bool)
	return enabled
}
