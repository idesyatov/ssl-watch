package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInternalHasTestFiles checks for the presence of test files in the internal directory.
func TestInternalHasTestFiles(t *testing.T) {
  // Specify the path to the internal directory
  internalDir := "./internal"

  // Use filepath.Walk to recursively traverse all files and subdirectories in the internal directory
  err := filepath.Walk(internalDir, func(path string, info os.FileInfo, err error) error {
    // If an error occurred while getting file information, return the error
    if err != nil {
      return err
    }

    // Check if the current item is a file and has the _test.go extension
    if !info.IsDir() && filepath.Ext(info.Name()) == "_test.go" {
      // Log a message about the found test file
      t.Logf("Found test file: %s", path)
    }

    // Return nil to continue the traversal
    return nil
  })

  // If an error occurred while traversing the directory, terminate the test with an error
  if err != nil {
    t.Fatalf("Error while traversing the directory: %v", err)
  }
}
