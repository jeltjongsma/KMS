package id

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateUUIDv4_Repeats(t *testing.T) {
	valid, err := GenerateUUID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 10; i++ {
		// name each sub-test so you can see which iteration fails
		t.Run(fmt.Sprintf("iteration_%02d", i+1), func(t *testing.T) {
			if err := validateUUIDv4(valid); err != nil {
				t.Errorf("iteration %d: expected no error, got %v", i+1, err)
			}
		})
	}
}

func TestValidateUUIDv4_Repeats_WithInvalids(t *testing.T) {
	cases := []struct {
		uuid      string
		shouldErr bool
	}{
		{"f47ac10b-58cc-4372-a567-0e02b2c3d479", false}, // valid
		{"z47ac10b-58cc-4372-a567-0e02b2c3d479", true},  // non-hex
		{"f47ac10b58cc4372a5670e02b2c3d479", true},      // missing hyphens
		{"f47ac10b-58cc-5372-a567-0e02b2c3d479", true},  // wrong version
		{"f47ac10b-58cc-4372-c567-0e02b2c3d479", true},  // wrong variant
	}

	for i := 0; i < 10; i++ {
		for _, tc := range cases {
			name := fmt.Sprintf("iter_%02d/%s", i+1, tc.uuid)
			t.Run(name, func(t *testing.T) {
				err := validateUUIDv4(tc.uuid)
				if (err != nil) != tc.shouldErr {
					t.Errorf("uuid=%q, iteration=%d, want err=%v, got %v", tc.uuid, i+1, tc.shouldErr, err)
				}
			})
		}
	}
}

func validateUUIDv4(uuid string) error {
	// Must be 36 characters: 32 hex + 4 hyphens
	if len(uuid) != 36 {
		return errors.New("invalid length")
	}

	// Must have hyphens in the correct places
	if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return errors.New("invalid hyphen placement")
	}

	// Check version (char at position 14)
	if uuid[14] != '4' {
		return fmt.Errorf("invalid version: expected 4, got %c", uuid[14])
	}

	// Check variant (char at position 19)
	// Acceptable values are 8, 9, a, b (i.e. high bits are 10)
	variantChar := uuid[19]
	if !strings.ContainsRune("89abAB", rune(variantChar)) {
		return fmt.Errorf("invalid variant: got %c", variantChar)
	}

	// Check that all characters except hyphens are hex
	hexParts := strings.ReplaceAll(uuid, "-", "")
	_, err := hex.DecodeString(hexParts)
	if err != nil {
		return errors.New("non-hex characters found")
	}

	return nil
}
