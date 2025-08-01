package httputils

import (
	"encoding/json"
)

type JSONResponseWrapper[T any] struct {
	Raw     string
	Decoded T
}

func (w *JSONResponseWrapper[T]) UnmarshalJSON(data []byte) error {
	w.Raw = string(data)
	return json.Unmarshal(data, &w.Decoded)
}

func (w *JSONResponseWrapper[T]) String() string {
	return w.Raw
}
