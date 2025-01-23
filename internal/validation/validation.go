package validation

import "fmt"

// InputValidator defines an interface for validating input data.
type InputValidator interface {
	// Validate checks the correctness of the input data: domain and certificate file.
	// Returns an error if both parameters are empty.
	Validate(domain, certFile string) error
}

// DefaultInputValidator is an implementation of the InputValidator interface.
// It provides a standard mechanism for validating input data.
type DefaultInputValidator struct{}

// Validate checks that at least one of the parameters (domain or certFile) is not empty.
// If both parameters are empty, it returns an error.
func (v *DefaultInputValidator) Validate(domain, certFile string) error {
	if domain == "" && certFile == "" {
		return fmt.Errorf("either domain or certfile must be specified")
	}
	return nil
}

// NewDefaultInputValidator creates and returns a new instance of DefaultInputValidator,
// which implements the InputValidator interface.
func NewDefaultInputValidator() InputValidator {
	return &DefaultInputValidator{}
}
