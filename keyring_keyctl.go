//go:build linux

package keyring

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/jsipprell/keyctl"
)

type keyctlProvider struct{}

func init() {
	// Set keyctl as the fallback provider for Linux
	getFallbackProvider = func() Keyring {
		return keyctlProvider{}
	}
}

// Set stores user and pass in the keyring under the defined service name using keyctl.
func (k keyctlProvider) Set(service, user, pass string) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Check if key already exists and remove it
	existingKey, err := keyring.Search(keyName)
	if err == nil {
		// Key exists, unlink it first
		_ = existingKey.Unlink()
	}

	// Add the new key
	_, err = keyring.Add(keyName, []byte(pass))
	return err
}

// Get gets a secret from the keyring given a service name and a user using keyctl.
func (k keyctlProvider) Get(service, user string) (string, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return "", err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Search for the key
	key, err := keyring.Search(keyName)
	if err != nil {
		return "", ErrNotFound
	}

	// Get the key data
	data, err := key.Get()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Delete deletes a secret, identified by service & user, from the keyring using keyctl.
func (k keyctlProvider) Delete(service, user string) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	// Search for the key
	key, err := keyring.Search(keyName)
	if err != nil {
		return ErrNotFound
	}

	// Unlink the key
	return key.Unlink()
}

// DeleteAll deletes all secrets for a given service using keyctl.
// This implementation uses the keyctl command-line tool to find matching keys.
func (k keyctlProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return err
	}

	// Use the keyctl command to list keys and find ones matching our service
	// The format of 'keyctl show @s' output is:
	// Session Keyring
	//  keyid perms  uid   gid description
	cmd := exec.Command("keyctl", "show", "@s")
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
		key, err := keyring.Search(keyDesc)
		if err == nil {
			_ = key.Unlink()
		}
	}

	return nil
}
