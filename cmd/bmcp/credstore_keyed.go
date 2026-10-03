package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// keyedBackend is the primitive the OS secret stores share: opaque blobs under
// a name, within one service. keyedStore maps credStore onto it, so the
// keychain and Secret Service backends hold item naming in one place.
type keyedBackend interface {
	name() backendName
	get(item string) ([]byte, error) // errStoreItemNotFound when absent
	set(item, label string, data []byte) error
	del(item string) error // nil when absent
	list() ([]string, error)
}

type keyedStore struct{ b keyedBackend }

func tokenItem(key string) string             { return "sso-token:" + key }
func roleItemPrefix(sessionKey string) string { return "role-creds:" + sessionKey + ":" }
func roleItem(sessionKey, credKey string) string {
	return roleItemPrefix(sessionKey) + credKey
}

func (s keyedStore) Backend() backendName { return s.b.name() }

func (s keyedStore) getJSON(item string, v any) error {
	data, err := s.b.get(item)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %s: %w", errStoreItemCorrupt, item, err)
	}
	return nil
}

func (s keyedStore) setJSON(item, label string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.b.set(item, label, data)
}

func (s keyedStore) ReadToken(key string) (ssoTokenRecord, error) {
	var rec ssoTokenRecord
	if err := validStoreKey(key); err != nil {
		return rec, err
	}
	return rec, s.getJSON(tokenItem(key), &rec)
}

func (s keyedStore) WriteToken(key string, rec ssoTokenRecord) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	return s.setJSON(tokenItem(key), "bmcp SSO token", rec)
}

func (s keyedStore) DeleteToken(key string) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	return s.b.del(tokenItem(key))
}

func (s keyedStore) ReadRoleCreds(sessionKey, credKey string) (roleCredsRecord, error) {
	var rec roleCredsRecord
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return rec, err
	}
	return rec, s.getJSON(roleItem(sessionKey, credKey), &rec)
}

func (s keyedStore) WriteRoleCreds(sessionKey, credKey string, rec roleCredsRecord) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	return s.setJSON(roleItem(sessionKey, credKey), "bmcp AWS role credentials", rec)
}

func (s keyedStore) DeleteRoleCreds(sessionKey, credKey string) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	return s.b.del(roleItem(sessionKey, credKey))
}

func (s keyedStore) DeleteSessionRoleCreds(sessionKey string) error {
	if err := validStoreKey(sessionKey); err != nil {
		return err
	}
	return s.deleteMatching(func(item string) bool { return strings.HasPrefix(item, roleItemPrefix(sessionKey)) })
}

func (s keyedStore) ClearAll([]string) error {
	return s.deleteMatching(func(string) bool { return true })
}

func (s keyedStore) deleteMatching(match func(string) bool) error {
	items, err := s.b.list()
	if err != nil {
		return err
	}
	var errs []error
	for _, item := range items {
		if match(item) {
			if err := s.b.del(item); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
