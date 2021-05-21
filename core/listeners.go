package core

import "context"

type StartListener interface {
	OnMutStart(ctx context.Context)
}
