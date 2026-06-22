// Command ssl-watch inspects and monitors TLS/SSL certificates from the command
// line. All application logic lives in internal/app; this is just the entrypoint.
package main

import (
	"os"

	"github.com/idesyatov/ssl-watch/internal/app"
)

func main() {
	os.Exit(app.Run())
}
