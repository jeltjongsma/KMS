package integration

import (
	"kms/internal/keys"
	"testing"
)

func TestCreateKey_UniqueConstraint(t *testing.T) {
	tests := []struct {
		name     string
		clientId int
		keyRef   string
		version  int
		wantErr  bool
	}{
		{"clientId 1, keyRef keyRef1, version 1", 1, "keyRef1", 1, false},
		{"clientId 1, keyRef keyRef1, version 2", 1, "keyRef1", 2, false},
		{"clientId 1, keyRef keyRef2, version 1", 1, "keyRef2", 1, false},
		{"clientId 2, keyRef keyRef1, version 1", 2, "keyRef1", 1, false},
		{"clientId 1, keyRef keyRef1, version 1 (duplicate)", 1, "keyRef1", 1, true},
		{"clientId 1, keyRef keyRef2, version 1 (duplicate)", 1, "keyRef2", 1, true},
		{"clientId 2, keyRef keyRef1, version 1 (duplicate)", 2, "keyRef1", 1, true},
		{"clientId 1, keyRef keyRef1, version 2 (duplicate)", 1, "keyRef1", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &keys.Key{
				ClientId:     tt.clientId,
				KeyReference: tt.keyRef,
				Version:      tt.version,
				DEK:          "someDEK",
				State:        "active",
				Encoding:     "base64",
			}
			_, err := appCtx.KeyRepo.CreateKey(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
