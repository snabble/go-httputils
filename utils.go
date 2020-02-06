package httputils

import "fmt"

func wrapError(err error, message string, args ...interface{}) error {
	return fmt.Errorf(message+": %w", err)
}

func wrapErrorF(err error, message string, args ...interface{}) error {
	return fmt.Errorf(message+": %w", append(args, err)...)
}
