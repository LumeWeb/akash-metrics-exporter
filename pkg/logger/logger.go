package logger

import (
    "github.com/sirupsen/logrus"
    "os"
)

var Log = logrus.New()

func init() {
    // Set default format
    Log.SetFormatter(&logrus.TextFormatter{
        FullTimestamp: true,
    })

    // Set output to stdout
    Log.SetOutput(os.Stdout)

    // Set level based on env var
    if os.Getenv("DEBUG_METRICS") == "true" {
        Log.SetLevel(logrus.DebugLevel)
    } else {
        Log.SetLevel(logrus.InfoLevel)
    }
}
