package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func ConvertTimestamp(timestampStr string) (time.Time, error) {
	parts := strings.Split(timestampStr, ".")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid timestamp format")
	}

	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing seconds: %w", err)
	}

	// take the first 9 digits for nanoseconds
	nanoseconds := int64(0)
	if len(parts[1]) > 0 {
		nanoseconds, err = strconv.ParseInt(parts[1][:9], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("error parsing nanoseconds: %w", err)
		}
	}

	return time.Unix(seconds, nanoseconds), nil
}
