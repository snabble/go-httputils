package httputils

import (
	"encoding/json"
)

type JSONResponseWrapper[T any] struct {
	Raw     []byte
	Decoded T
}

func (w *JSONResponseWrapper[T]) UnmarshalJSON(data []byte) error {
	w.Raw = make([]byte, len(data))
	copy(w.Raw, data)
	return json.Unmarshal(data, &w.Decoded)
}

func (w *JSONResponseWrapper[T]) String() string {
	return string(w.Raw)
}
