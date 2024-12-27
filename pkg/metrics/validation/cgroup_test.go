package validation

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateCgroups(t *testing.T) {
	v := ValidateCgroups()
	assert.NotNil(t, v)
	assert.NotNil(t, v.Stats)
	assert.NotNil(t, v.Errors)
	assert.NotNil(t, v.Permissions)
	assert.NotNil(t, v.MountPoints)
}

func TestParseCPUStat(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected uint64
		hasError bool
	}{
		{
			name:     "valid input",
			input:    "usage_usec 12345\nuser_usec 23456\n",
			expected: 12345,
			hasError: false,
		},
		{
			name:     "missing usage_usec",
			input:    "user_usec 23456\n",
			expected: 0,
			hasError: true,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCPUStat(tc.input)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseMemoryCurrent(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected uint64
		hasError bool
	}{
		{
			name:     "valid input",
			input:    "12345\n",
			expected: 12345,
			hasError: false,
		},
		{
			name:     "invalid number",
			input:    "invalid",
			expected: 0,
			hasError: true,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseMemoryCurrent(tc.input)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseMemoryStats(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]uint64
		hasError bool
	}{
		{
			name:     "valid input",
			input:    "cache 12345\nanon 23456\n",
			expected: map[string]uint64{"cache": 12345, "anon": 23456},
			hasError: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]uint64{},
			hasError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseMemoryStats(tc.input)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseIOStat(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]map[string]uint64
		hasError bool
	}{
		{
			name:  "valid input",
			input: "8:0 rbytes=12345 wbytes=23456\n8:1 rbytes=34567 wbytes=45678\n",
			expected: map[string]map[string]uint64{
				"8:0": {"rbytes": 12345, "wbytes": 23456},
				"8:1": {"rbytes": 34567, "wbytes": 45678},
			},
			hasError: false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]map[string]uint64{},
			hasError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseIOStat(tc.input)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
