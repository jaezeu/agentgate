package vaultapi

import (
	"context"
	"errors"
	"fmt"

	hashicorpapi "github.com/hashicorp/vault/api"
)

var (
	ErrInvalidConfiguration = errors.New("invalid Vault manager configuration")
	ErrInvalidBinding       = errors.New("invalid Vault access binding")
	ErrBindingConflict      = errors.New("vault access binding conflicts with existing configuration")
	ErrVaultOperation       = errors.New("vault control-plane operation failed")
)

// FieldError identifies invalid configuration or binding data without echoing its value.
type FieldError struct {
	Kind   error
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Kind, e.Field, e.Reason)
}

func (e *FieldError) Unwrap() error {
	return e.Kind
}

// ConflictError identifies a request-scoped resource that does not match the binding.
type ConflictError struct {
	RequestID string
	Resource  string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s: request %q resource %q", ErrBindingConflict, e.RequestID, e.Resource)
}

func (e *ConflictError) Unwrap() error {
	return ErrBindingConflict
}

// OperationError omits Vault response bodies and preserves only cancellation causes.
type OperationError struct {
	Operation  string
	Resource   string
	StatusCode int
	cause      error
}

func (e *OperationError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("%s: %s %q returned HTTP %d", ErrVaultOperation, e.Operation, e.Resource, e.StatusCode)
	}
	return fmt.Sprintf("%s: %s %q", ErrVaultOperation, e.Operation, e.Resource)
}

func (e *OperationError) Unwrap() error {
	return e.cause
}

func (e *OperationError) Is(target error) bool {
	return target == ErrVaultOperation
}

func newOperationError(operation, resource string, cause error) *OperationError {
	var responseError *hashicorpapi.ResponseError
	statusCode := 0
	if errors.As(cause, &responseError) {
		statusCode = responseError.StatusCode
		cause = nil
	} else if !errors.Is(cause, context.Canceled) &&
		!errors.Is(cause, context.DeadlineExceeded) {
		cause = nil
	}
	return &OperationError{
		Operation:  operation,
		Resource:   resource,
		StatusCode: statusCode,
		cause:      cause,
	}
}
