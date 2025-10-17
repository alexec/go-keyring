//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package keyring

import (
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	ss "github.com/zalando/go-keyring/secret_service"
)

// compositeProvider tries Secret Service first, then falls back to keyctl on Linux
type compositeProvider struct {
	primary  Keyring
	fallback Keyring
}

func (c compositeProvider) Set(service, user, pass string) error {
	err := c.primary.Set(service, user, pass)
	if err != nil && c.fallback != nil {
		return c.fallback.Set(service, user, pass)
	}
	return err
}

func (c compositeProvider) Get(service, user string) (string, error) {
	result, err := c.primary.Get(service, user)
	if err != nil && c.fallback != nil {
		return c.fallback.Get(service, user)
	}
	return result, err
}

func (c compositeProvider) Delete(service, user string) error {
	err := c.primary.Delete(service, user)
	if err != nil && c.fallback != nil {
		return c.fallback.Delete(service, user)
	}
	return err
}

func (c compositeProvider) DeleteAll(service string) error {
	err := c.primary.DeleteAll(service)
	if err != nil && c.fallback != nil {
		return c.fallback.DeleteAll(service)
	}
	return err
}

type secretServiceProvider struct{}

// Set stores user and pass in the keyring under the defined service
// name.
func (s secretServiceProvider) Set(service, user, pass string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return err
	}
	defer svc.Close(session)

	attributes := map[string]string{
		"username": user,
		"service":  service,
	}

	secret := ss.NewSecret(session.Path(), pass)

	collection := svc.GetLoginCollection()

	err = svc.Unlock(collection.Path())
	if err != nil {
		return err
	}

	err = svc.CreateItem(collection,
		fmt.Sprintf("Password for '%s' on '%s'", user, service),
		attributes, secret)
	if err != nil {
		return err
	}

	return nil
}

// findItem looksup an item by service and user.
func (s secretServiceProvider) findItem(svc *ss.SecretService, service, user string) (dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"username": user,
		"service":  service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return "", err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "", ErrNotFound
	}

	return results[0], nil
}

// findServiceItems looksup all items by service.
func (s secretServiceProvider) findServiceItems(svc *ss.SecretService, service string) ([]dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"service": service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	if len(results) == 0 {
		return []dbus.ObjectPath{}, ErrNotFound
	}

	return results, nil
}

// Get gets a secret from the keyring given a service name and a user.
func (s secretServiceProvider) Get(service, user string) (string, error) {
	svc, err := ss.NewSecretService()
	if err != nil {
		return "", err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return "", err
	}

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return "", err
	}
	defer svc.Close(session)

	// unlock if invdividual item is locked
	err = svc.Unlock(item)
	if err != nil {
		return "", err
	}

	secret, err := svc.GetSecret(item, session.Path())
	if err != nil {
		return "", err
	}

	return string(secret.Value), nil
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (s secretServiceProvider) Delete(service, user string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return err
	}

	return svc.Delete(item)
}

// DeleteAll deletes all secrets for a given service
func (s secretServiceProvider) DeleteAll(service string) error {
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}

	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}
	// find all items for the service
	items, err := s.findServiceItems(svc, service)
	if err != nil {
		if err == ErrNotFound {
			return nil
		}
		return err
	}
	for _, item := range items {
		err = svc.Delete(item)
		if err != nil {
			return err
		}
	}
	return nil
}

// getFallbackProvider returns the appropriate fallback provider for the platform
// Defined in platform-specific files (e.g., keyring_keyctl.go for Linux)
var getFallbackProvider = func() Keyring {
	return nil
}

func init() {
	// Try to initialize Secret Service
	svc, err := ss.NewSecretService()
	if err == nil {
		// Secret Service is available
		svc.Close(nil)
		provider = secretServiceProvider{}
	} else {
		// Secret Service not available, use compositeProvider with fallback
		// Note: We still try Secret Service as primary for forward compatibility
		// but will fallback to keyctl if it's not available
		fallback := getFallbackProvider()
		if fallback != nil {
			provider = compositeProvider{
				primary:  secretServiceProvider{},
				fallback: fallback,
			}
		} else {
			// No fallback available, keep using Secret Service (will error on operations)
			provider = secretServiceProvider{}
		}
	}
}
