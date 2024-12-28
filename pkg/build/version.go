package build

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current version of the application
	Version = "dev"
	
	// GitCommit is the git commit hash
	GitCommit = "unknown"
	
	// BuildTime is the build timestamp
	BuildTime = "unknown"
)

// GetVersionInfo returns a formatted string with version details
func GetVersionInfo() string {
	return fmt.Sprintf(
		"Version: %s\nGit Commit: %s\nBuild Time: %s\nGo Version: %s\nOS/Arch: %s/%s",
		Version,
		GitCommit,
		BuildTime,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
}
