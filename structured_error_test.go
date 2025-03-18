package httputils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StructuredError_Error(t *testing.T) {
	e := StructuredError{
		Type:    "__type__",
		Message: "__message__",
	}
	assert.Equal(t, "__type__: __message__", e.Error(), "should be equal")
}

func Test_StructuredError_Is(t *testing.T) {
	e1 := StructuredError{Type: "__type_one__", Message: "__message_one__"}
	e2 := StructuredError{Type: "__type_two__", Message: "__message_two__"}

	assert.True(t, errors.Is(e1, e1), "e1 should be the same as e1")
	assert.True(t, errors.Is(e1, e2), "e1 should be the same type as e2")

	eNonStructured := errors.New("some other error")
	assert.False(t, errors.Is(e1, eNonStructured), "e1 should not be the same type as a non-structured error")
}
