//go:build linux

package keyring

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

type keyctlProvider struct{}

func init() {
	// Set keyctl as the fallback provider for Linux
	getFallbackProvider = func() Keyring {
		return keyctlProvider{}
	}
}

// getPersistentKeyring gets or creates the persistent keyring for the current user.
// The persistent keyring survives logout and persists across multiple sessions,
// with a default expiry of 3 days (resettable on each access).
func (k keyctlProvider) getPersistentKeyring() (int, error) {
	// Get the persistent keyring for the current user
	// KEYCTL_GET_PERSISTENT with -1 means current UID
	persistentKeyringID, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, -1, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get persistent keyring: %w", err)
	}
	return persistentKeyringID, nil
}

// Set stores user and pass in the keyring under the defined service name using keyctl.
func (k keyctlProvider) Set(service, user, pass string) error {
	// Get the persistent keyring ID
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Check if key already exists and remove it
	existingKeyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err == nil {
		// Key exists, unlink it first
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, existingKeyID, persistentKeyring, 0, 0)
	}

	// Add the new key
	_, err = unix.AddKey("user", keyName, []byte(pass), persistentKeyring)
	return err
}

// Get gets a secret from the keyring given a service name and a user using keyctl.
func (k keyctlProvider) Get(service, user string) (string, error) {
	// Get the persistent keyring ID
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return "", err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Search for the key
	keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err != nil {
		return "", ErrNotFound
	}

	// Read the key data
	// First, get the size of the key
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, nil, 0)
	if err != nil {
		return "", err
	}

	// Allocate buffer and read the key
	buf := make([]byte, size)
	_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// Delete deletes a secret, identified by service & user, from the keyring using keyctl.
func (k keyctlProvider) Delete(service, user string) error {
	// Get the persistent keyring ID
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Search for the key
	keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err != nil {
		return ErrNotFound
	}

	// Unlink the key from the persistent keyring
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, persistentKeyring, 0, 0)
	return err
}

// DeleteAll deletes all secrets for a given service using keyctl.
// This implementation uses the keyctl command-line tool to find matching keys.
func (k keyctlProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	// Get the persistent keyring ID
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	// Use the keyctl command to list keys in the persistent keyring
	// The persistent keyring ID format is a decimal number
	cmd := exec.Command("keyctl", "show", fmt.Sprintf("%d", persistentKeyring))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If keyctl command fails, return nil (no keys to delete)
		return nil
	}

	// Parse the output to find keys that match our service
	lines := strings.Split(string(output), "\n")
	prefix := fmt.Sprintf("%s:", service)

	for _, line := range lines {
		// Look for lines containing our service prefix
		// Format: " keyid --perms uid gid   \_ user: service:username"
		if !strings.Contains(line, prefix) {
			continue
		}

		// Extract the key description (after "user: ")
		parts := strings.Split(line, "user:")
		if len(parts) < 2 {
			continue
		}

		keyDesc := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(keyDesc, service+":") {
			continue
		}

		// Search for the key by its full description and delete it
		keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyDesc, 0)
		if err == nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, persistentKeyring, 0, 0)
		}
	}

	return nil
}
