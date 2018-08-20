package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevelCase(t *testing.T) {
	assert.NoError(t, NewLoggerLevel("DEBUG", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("debug", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("InFo", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("INFO", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("WARN", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("WARNING", DefaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("notReal", DefaultLogFilePath, false))
}
