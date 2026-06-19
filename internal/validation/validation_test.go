package validation

import (
	"fmt"
	"testing"
)

// TestDefaultInputValidator tests the Validate method of the DefaultInputValidator.
// It checks various combinations of domain and certificate file inputs to ensure
// that the validation logic behaves as expected.
func TestDefaultInputValidator(t *testing.T) {
	// Create a new instance of the DefaultInputValidator
	val := NewDefaultInputValidator()

	// Define test cases with expected outcomes
	tests := []struct {
		domain   string
		certFile string
		expected error
	}{
		// Test case where both domain and certFile are empty
		{"", "", fmt.Errorf("either domain or certfile must be specified")},
		// Test case where only domain is provided
		{"example.com", "", nil},
		// Test case where only certFile is provided
		{"", "cert.pem", nil},
		// Test case where both domain and certFile are provided
		{"example.com", "cert.pem", nil},
	}

	// Iterate over each test case
	for _, test := range tests {
		// Run a sub-test for each case with a descriptive name
		t.Run(fmt.Sprintf("domain=%s, certFile=%s", test.domain, test.certFile), func(t *testing.T) {
			// Call the Validate method with the test inputs
			err := val.Validate(test.domain, test.certFile)

			// Check if the error presence matches the expected outcome
			if (err != nil) != (test.expected != nil) {
				t.Errorf("expected error: %v, got: %v", test.expected, err)
			} else if err != nil && err.Error() != test.expected.Error() {
				// If an error occurred, check if the error message matches the expected message
				t.Errorf("expected error message: %v, got: %v", test.expected.Error(), err.Error())
			}
		})
	}
}
