package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
)

// awsCLICacheStore keeps the token where the AWS CLI and the SDK look for it,
// ~/.aws/sso/cache/<key>.json, and role credentials in bmcp's own cache dir,
// since the CLI has no file for them that bmcp could share.
type awsCLICacheStore struct {
	tokenDir string
	credsDir string
}

func newAWSCLICacheStore() (*awsCLICacheStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cache, err := bmcpCacheDir()
	if err != nil {
		return nil, err
	}
	return &awsCLICacheStore{
		tokenDir: filepath.Join(home, ".aws", "sso", "cache"),
		credsDir: filepath.Join(cache, "creds"),
	}, nil
}

func (s *awsCLICacheStore) Backend() backendName { return backendAWSCLICache }

func (s *awsCLICacheStore) tokenPath(key string) string {
	return filepath.Join(s.tokenDir, key+".json")
}

func (s *awsCLICacheStore) credPath(sessionKey, credKey string) string {
	return filepath.Join(s.credsDir, sessionKey, credKey+".json")
}

func (s *awsCLICacheStore) ReadToken(key string) (ssoTokenRecord, error) {
	var rec ssoTokenRecord
	if err := validStoreKey(key); err != nil {
		return rec, err
	}
	return rec, readJSONFile(s.tokenPath(key), &rec)
}

func (s *awsCLICacheStore) WriteToken(key string, rec ssoTokenRecord) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(s.tokenPath(key), b)
}

func (s *awsCLICacheStore) DeleteToken(key string) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	return removeIfExists(s.tokenPath(key))
}

func (s *awsCLICacheStore) ReadRoleCreds(sessionKey, credKey string) (roleCredsRecord, error) {
	var rec roleCredsRecord
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return rec, err
	}
	return rec, readJSONFile(s.credPath(sessionKey, credKey), &rec)
}

func (s *awsCLICacheStore) WriteRoleCreds(sessionKey, credKey string, rec roleCredsRecord) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(s.credPath(sessionKey, credKey), b)
}

func (s *awsCLICacheStore) DeleteRoleCreds(sessionKey, credKey string) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	return removeIfExists(s.credPath(sessionKey, credKey))
}

func (s *awsCLICacheStore) DeleteSessionRoleCreds(sessionKey string) error {
	if err := validStoreKey(sessionKey); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.credsDir, sessionKey))
}

func (s *awsCLICacheStore) ClearAll(sessionKeys []string) error {
	var errs []error
	for _, k := range sessionKeys {
		if err := s.DeleteToken(k); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(s.credsDir); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validStoreKeys(keys ...string) error {
	for _, k := range keys {
		if err := validStoreKey(k); err != nil {
			return err
		}
	}
	return nil
}

// readJSONFile maps a missing file to errStoreItemNotFound. An unparseable one
// is reported as such; the CLI writes non-atomically, so a caller racing it may
// see a truncated file and should treat that as no token.
func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return errStoreItemNotFound
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %s is not JSON: %w", errStoreItemCorrupt, path, err)
	}
	return nil
}

// fileStore encrypts each item to its own file under ~/.config/bmcp/keys/, so
// writes for two sessions never read-modify-write one shared file.
type fileStore struct {
	dir  string
	opts storeOptions

	mu         sync.Mutex
	passphrase string
}

// fileStoreHeader precedes the age payload so a future format can be told
// apart without trying to decrypt it.
const fileStoreHeader = "bmcp-credstore-v1\n"

// fileStoreWorkFactor is scrypt's log2(N). age's default of 18 costs about a
// second per item, and an agent call reads two; 15 keeps it near 100ms.
var fileStoreWorkFactor = 15

const fileStoreMaxWorkFactor = 22

func newFileStore(opts storeOptions) (*fileStore, error) {
	cfg, err := bmcpConfigDir()
	if err != nil {
		return nil, err
	}
	return &fileStore{dir: filepath.Join(cfg, "keys"), opts: opts}, nil
}

func (s *fileStore) Backend() backendName { return backendFile }

func (s *fileStore) tokenPath(key string) string {
	return filepath.Join(s.dir, "token-"+key+".age")
}

func (s *fileStore) credPath(sessionKey, credKey string) string {
	return filepath.Join(s.dir, "role-"+sessionKey+"-"+credKey+".age")
}

// pass prompts at most once per store, and only when UI is allowed: the env
// var is the only passphrase source an unattended run has.
func (s *fileStore) pass() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passphrase != "" {
		return s.passphrase, nil
	}
	if v := os.Getenv("BMCP_FILE_PASSPHRASE"); v != "" {
		s.passphrase = v
		return v, nil
	}
	if !s.opts.AllowUI || s.opts.Passphrase == nil {
		return "", &storeLockedError{Backend: backendFile, Reason: "no passphrase for the encrypted file store",
			Hint: "set BMCP_FILE_PASSPHRASE"}
	}
	v, err := s.opts.Passphrase("Passphrase for the bmcp credential file store: ")
	if err != nil {
		return "", &storeLockedError{Backend: backendFile, Reason: "passphrase prompt failed", Hint: "set BMCP_FILE_PASSPHRASE", Err: err}
	}
	if v == "" {
		return "", &storeLockedError{Backend: backendFile, Reason: "empty passphrase", Hint: "set BMCP_FILE_PASSPHRASE"}
	}
	s.passphrase = v
	return v, nil
}

func (s *fileStore) read(path string, v any) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return errStoreItemNotFound
	}
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(raw, []byte(fileStoreHeader)) {
		return fmt.Errorf("%w: %s is not a bmcp credential file (unknown format)", errStoreItemCorrupt, path)
	}
	pass, err := s.pass()
	if err != nil {
		return err
	}
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		return err
	}
	id.SetMaxWorkFactor(fileStoreMaxWorkFactor)
	r, err := age.Decrypt(bytes.NewReader(raw[len(fileStoreHeader):]), id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return &storeLockedError{Backend: backendFile, Reason: "the passphrase does not decrypt " + filepath.Base(path),
				Hint: "set BMCP_FILE_PASSPHRASE to the passphrase the store was written with, or run bmcp clear and log in again"}
		}
		return fmt.Errorf("decrypt %s: %w", path, err)
	}
	plain, err := io.ReadAll(bufio.NewReader(r))
	if err != nil {
		return fmt.Errorf("decrypt %s: %w", path, err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("%w: %s: %w", errStoreItemCorrupt, path, err)
	}
	return nil
}

func (s *fileStore) write(path string, v any) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	pass, err := s.pass()
	if err != nil {
		return err
	}
	rcpt, err := age.NewScryptRecipient(pass)
	if err != nil {
		return err
	}
	rcpt.SetWorkFactor(fileStoreWorkFactor)
	var out bytes.Buffer
	out.WriteString(fileStoreHeader)
	w, err := age.Encrypt(&out, rcpt)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return writeSecretFileAtomic(path, out.Bytes())
}

func (s *fileStore) ReadToken(key string) (ssoTokenRecord, error) {
	var rec ssoTokenRecord
	if err := validStoreKey(key); err != nil {
		return rec, err
	}
	return rec, s.read(s.tokenPath(key), &rec)
}

func (s *fileStore) WriteToken(key string, rec ssoTokenRecord) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	return s.write(s.tokenPath(key), rec)
}

func (s *fileStore) DeleteToken(key string) error {
	if err := validStoreKey(key); err != nil {
		return err
	}
	return removeIfExists(s.tokenPath(key))
}

func (s *fileStore) ReadRoleCreds(sessionKey, credKey string) (roleCredsRecord, error) {
	var rec roleCredsRecord
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return rec, err
	}
	return rec, s.read(s.credPath(sessionKey, credKey), &rec)
}

func (s *fileStore) WriteRoleCreds(sessionKey, credKey string, rec roleCredsRecord) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	return s.write(s.credPath(sessionKey, credKey), rec)
}

func (s *fileStore) DeleteRoleCreds(sessionKey, credKey string) error {
	if err := validStoreKeys(sessionKey, credKey); err != nil {
		return err
	}
	return removeIfExists(s.credPath(sessionKey, credKey))
}

// Deletion needs no passphrase: names alone say what an item is, which is
// what lets `bmcp clear` recover from a lost passphrase.
func (s *fileStore) DeleteSessionRoleCreds(sessionKey string) error {
	if err := validStoreKey(sessionKey); err != nil {
		return err
	}
	return s.removeMatching(func(name string) bool { return strings.HasPrefix(name, "role-"+sessionKey+"-") })
}

func (s *fileStore) ClearAll([]string) error {
	return s.removeMatching(func(name string) bool {
		return strings.HasPrefix(name, "token-") || strings.HasPrefix(name, "role-")
	})
}

func (s *fileStore) removeMatching(match func(string) bool) error {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".age") && match(e.Name()) {
			if err := removeIfExists(filepath.Join(s.dir, e.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
