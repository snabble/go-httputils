package httputils

import (
	"errors"
	"fmt"
)

// StructuredError represents a structured error containing a type and a message.
type StructuredError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Error implements the Error interface for StructuredError.
// It returns the error message formatted as "Type: Message".
func (s StructuredError) Error() string {
	return fmt.Sprintf("%s: %s", s.Type, s.Message)
}

// Is implements the Is method for the errors package.
// It checks whether the target error is a StructuredError.
func (s StructuredError) Is(target error) bool {
	return errors.As(target, &StructuredError{})
}
