package httputils

import (
	"context"
	"encoding/json"

	"github.com/snabble/go-logging/v2"
)

func WithDebug[T any](ctx context.Context, v T, name string) *DebugWrapper[T] {
	return &DebugWrapper[T]{value: v, name: name, ctx: ctx}
}

type DebugWrapper[T any] struct {
	value T
	name  string
	ctx   context.Context
}

func (w *DebugWrapper[T]) UnmarshalJSON(data []byte) error {
	logging.Log.WithContext(w.ctx).WithField(logging.ResponseField, string(data)).Debug("Received from " + w.name)

	err := json.Unmarshal(data, &w.value)

	return err
}

func (w DebugWrapper[T]) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(w.value)

	logging.Log.WithContext(w.ctx).WithField(logging.PayloadField, string(data)).Debug("Send to " + w.name)

	return data, err
}
