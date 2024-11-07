package httputils

import "encoding/json"

type JSONResponseWrapper[T any] struct {
	Raw     []byte
	Decoded T
}

func (w *JSONResponseWrapper[T]) UnmarshalJSON(data []byte) error {
	copy(w.Raw, data)
	return json.Unmarshal(data, &w.Decoded)
}
