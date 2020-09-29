package registry

import "fmt"

type Error interface {
	// Satisfy the generic error interface.
	error

	// Returns the HTTP error code the error.
	Code() int

	// Returns the original error if one was set.  Nil is returned if not set.
	OrigErr() error
}

type ClientError struct {
	code int
	err  error
}

func NewClientError(code int, err error) *ClientError {
	return &ClientError{
		code: code,
		err:  err,
	}
}

func (c *ClientError) Code() int {
	return c.code
}

func (c *ClientError) OrigErr() error {
	return c.err
}

func (c *ClientError) Error() string {
	return fmt.Sprintf("%d: %v\n", c.Code(), c.OrigErr())
}
