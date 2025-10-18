//go:build linux

package keyring

import (
	"testing"
)

// TestKeyctlProvider tests the keyctl provider directly
func TestKeyctlProvider(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-service"
	user := "test-keyctl-user"
	password := "test-keyctl-password"

	// Clean up before test
	_ = provider.Delete(service, user)

	// Test Set
	err := provider.Set(service, user, password)
	if err != nil {
		t.Fatalf("Failed to set password: %v", err)
	}

	// Test Get
	retrieved, err := provider.Get(service, user)
	if err != nil {
		t.Fatalf("Failed to get password: %v", err)
	}

	if retrieved != password {
		t.Errorf("Expected password %q, got %q", password, retrieved)
	}

	// Test Get non-existing
	_, err = provider.Get(service, "non-existing-user")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound for non-existing user, got %v", err)
	}

	// Test Delete
	err = provider.Delete(service, user)
	if err != nil {
		t.Fatalf("Failed to delete password: %v", err)
	}

	// Verify deletion
	_, err = provider.Get(service, user)
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound after deletion, got %v", err)
	}

	// Test Delete non-existing
	err = provider.Delete(service, "non-existing-user")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound for deleting non-existing user, got %v", err)
	}
}

// TestKeyctlProviderMultiLine tests multi-line passwords with keyctl
func TestKeyctlProviderMultiLine(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-multiline"
	user := "test-user"
	multilinePassword := `line1
line2
line3`

	// Clean up before test
	_ = provider.Delete(service, user)

	err := provider.Set(service, user, multilinePassword)
	if err != nil {
		t.Fatalf("Failed to set multiline password: %v", err)
	}

	retrieved, err := provider.Get(service, user)
	if err != nil {
		t.Fatalf("Failed to get multiline password: %v", err)
	}

	if retrieved != multilinePassword {
		t.Errorf("Expected multiline password %q, got %q", multilinePassword, retrieved)
	}

	// Clean up
	_ = provider.Delete(service, user)
}

// TestKeyctlProviderSpecialChars tests special characters with keyctl
func TestKeyctlProviderSpecialChars(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-special"
	user := "test-user"
	specialPassword := "p@ssw0rd!#$%^&*()üöäÜÖÄß"

	// Clean up before test
	_ = provider.Delete(service, user)

	err := provider.Set(service, user, specialPassword)
	if err != nil {
		t.Fatalf("Failed to set special chars password: %v", err)
	}

	retrieved, err := provider.Get(service, user)
	if err != nil {
		t.Fatalf("Failed to get special chars password: %v", err)
	}

	if retrieved != specialPassword {
		t.Errorf("Expected special chars password %q, got %q", specialPassword, retrieved)
	}

	// Clean up
	_ = provider.Delete(service, user)
}

// TestKeyctlProviderDeleteAll tests DeleteAll functionality with keyctl
func TestKeyctlProviderDeleteAll(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-deleteall"

	// Clean up before test
	_ = provider.DeleteAll(service)

	// Set multiple passwords for the same service
	users := []string{"user1", "user2", "user3"}
	for _, user := range users {
		err := provider.Set(service, user, "password-"+user)
		if err != nil {
			t.Fatalf("Failed to set password for %s: %v", user, err)
		}
	}

	// Verify all passwords are set
	for _, user := range users {
		_, err := provider.Get(service, user)
		if err != nil {
			t.Errorf("Failed to get password for %s after set: %v", user, err)
		}
	}

	// Delete all passwords for the service
	err := provider.DeleteAll(service)
	if err != nil {
		t.Fatalf("Failed to delete all passwords: %v", err)
	}

	// Verify all passwords are deleted
	for _, user := range users {
		_, err := provider.Get(service, user)
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound for %s after DeleteAll, got %v", user, err)
		}
	}
}

// TestKeyctlProviderDeleteAllEmpty tests DeleteAll with empty service
func TestKeyctlProviderDeleteAllEmpty(t *testing.T) {
	provider := keyctlProvider{}

	err := provider.DeleteAll("")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound for empty service, got %v", err)
	}
}

// TestKeyctlProviderUpdate tests updating an existing password
func TestKeyctlProviderUpdate(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-update"
	user := "test-user"
	password1 := "password1"
	password2 := "password2"

	// Clean up before test
	_ = provider.Delete(service, user)

	// Set initial password
	err := provider.Set(service, user, password1)
	if err != nil {
		t.Fatalf("Failed to set initial password: %v", err)
	}

	// Update password
	err = provider.Set(service, user, password2)
	if err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	// Verify updated password
	retrieved, err := provider.Get(service, user)
	if err != nil {
		t.Fatalf("Failed to get updated password: %v", err)
	}

	if retrieved != password2 {
		t.Errorf("Expected updated password %q, got %q", password2, retrieved)
	}

	// Clean up
	_ = provider.Delete(service, user)
}

// TestKeyctlProviderMultipleServices tests isolation between different services
func TestKeyctlProviderMultipleServices(t *testing.T) {
	provider := keyctlProvider{}

	service1 := "test-keyctl-service1"
	service2 := "test-keyctl-service2"
	user := "test-user"
	password1 := "password1"
	password2 := "password2"

	// Clean up before test
	_ = provider.Delete(service1, user)
	_ = provider.Delete(service2, user)

	// Set passwords for different services
	err := provider.Set(service1, user, password1)
	if err != nil {
		t.Fatalf("Failed to set password for service1: %v", err)
	}

	err = provider.Set(service2, user, password2)
	if err != nil {
		t.Fatalf("Failed to set password for service2: %v", err)
	}

	// Verify passwords are isolated
	retrieved1, err := provider.Get(service1, user)
	if err != nil {
		t.Fatalf("Failed to get password for service1: %v", err)
	}

	retrieved2, err := provider.Get(service2, user)
	if err != nil {
		t.Fatalf("Failed to get password for service2: %v", err)
	}

	if retrieved1 != password1 {
		t.Errorf("Expected password %q for service1, got %q", password1, retrieved1)
	}

	if retrieved2 != password2 {
		t.Errorf("Expected password %q for service2, got %q", password2, retrieved2)
	}

	// Delete service1, verify service2 is unaffected
	err = provider.Delete(service1, user)
	if err != nil {
		t.Fatalf("Failed to delete password for service1: %v", err)
	}

	_, err = provider.Get(service1, user)
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound for service1 after deletion, got %v", err)
	}

	retrieved2, err = provider.Get(service2, user)
	if err != nil {
		t.Fatalf("Failed to get password for service2 after deleting service1: %v", err)
	}

	if retrieved2 != password2 {
		t.Errorf("Expected password %q for service2 after deleting service1, got %q", password2, retrieved2)
	}

	// Clean up
	_ = provider.Delete(service2, user)
}

// TestKeyctlProviderEmptyPassword tests that empty passwords return an error
// Note: keyctl does not support storing empty values
func TestKeyctlProviderEmptyPassword(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-empty"
	user := "test-user"
	emptyPassword := ""

	// Clean up before test
	_ = provider.Delete(service, user)

	err := provider.Set(service, user, emptyPassword)
	// keyctl does not support empty passwords, so we expect an error
	if err == nil {
		t.Errorf("Expected error when setting empty password, got nil")
		// Clean up if it somehow succeeded
		_ = provider.Delete(service, user)
	}
}

// TestKeyctlProviderBinaryData tests storing and retrieving binary data
func TestKeyctlProviderBinaryData(t *testing.T) {
	provider := keyctlProvider{}

	service := "test-keyctl-binary"
	user := "test-user"
	binaryPassword := string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

	// Clean up before test
	_ = provider.Delete(service, user)

	err := provider.Set(service, user, binaryPassword)
	if err != nil {
		t.Fatalf("Failed to set binary password: %v", err)
	}

	retrieved, err := provider.Get(service, user)
	if err != nil {
		t.Fatalf("Failed to get binary password: %v", err)
	}

	if retrieved != binaryPassword {
		t.Errorf("Expected binary password %v, got %v", []byte(binaryPassword), []byte(retrieved))
	}

	// Clean up
	_ = provider.Delete(service, user)
}
