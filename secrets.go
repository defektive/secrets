package secrets

import (
	"errors"
	"log"
	"strings"

	"github.com/godbus/dbus/v5"
	keyring "github.com/ppacher/go-dbus-keyring"
)

type Credential struct {
	URL      string
	Username string
	Password string
}

var Debug = false

func logError(err error, when string) {
	if err != nil && Debug {
		log.Printf("error %s: %s", when, err)
	}
}

func logErrorReturnString(err error, when string) string {
	logError(err, when)
	return ""
}

type Session struct {
	Conn           *dbus.Conn
	SecretsService keyring.SecretService
	Session        keyring.Session
}

func NewSession() (*Session, error) {

	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}

	svc, err := keyring.GetSecretService(conn)
	if err != nil {
		return nil, err
	}

	// session is required to create/retrieve secrets
	session, err := svc.OpenSession()
	if err != nil {
		return nil, err
	}

	return &Session{
		conn,
		svc,
		session,
	}, nil
}

func (s *Session) Close() error {
	return s.Session.Close()
}

func (s *Session) Search(search map[string]string) ([]keyring.Item, []keyring.Item, error) {
	return s.SecretsService.SearchItems(search)
}

func (s *Session) getItemSecret(item keyring.Item) (string, error) {

	secret, err := item.GetSecret(s.Session.Path())
	if err != nil {
		return "", err
	}
	return string(secret.Value), nil
}

func (s *Session) GetCredential(label string) (*Credential, error) {

	search := map[string]string{
		"Title": label,
	}

	crazyMap := map[string][]keyring.Item{}
	unlocked, locked, err := s.Search(search)
	if err != nil {
		return nil, err
	}

	crazyMap["unlocked"] = unlocked
	crazyMap["locked"] = locked

	for stat, items := range crazyMap {

		for _, item := range items {
			if stat == "locked" {
				_, err = item.Unlock()
				if err != nil {
					logError(err, "unlocking item")
					continue
				}
			}

			str, err := s.getItemSecret(item)
			if err != nil {
				return nil, err
			}

			credential, err := itemToCredential(item)
			if err != nil {
				log.Printf("something went wrong while converting an item to creds: %s", err)
			}
			credential.Password = str
			return credential, nil
		}
	}

	return nil, errors.New("no match found")
}

func (s *Session) GetSecret(label string) (string, error) {
	cred, err := s.GetCredential(label)
	if err != nil {
		return "", err
	}

	return cred.Password, nil
}

func GetSecret(label string) string {
	session, err := NewSession()
	if err != nil {
		return logErrorReturnString(err, "creating new session")
	}
	defer func() {
		err := session.Close()
		if err != nil {
			logError(err, "closing session")
		}
	}()

	secStr, err := session.GetSecret(label)
	if err != nil {
		return logErrorReturnString(err, "get secret")

	}

	return secStr
}

func GetCredential(label string) (*Credential, error) {
	session, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		err := session.Close()
		if err != nil {
			logError(err, "closing session")
		}
	}()

	return session.GetCredential(label)
}

func itemToCredential(item keyring.Item) (*Credential, error) {
	attrs, err := item.GetAttributes()
	if err != nil {
		return nil, err
	}

	credential := &Credential{}

	for key, val := range attrs {
		if keyIsUsername(key) {
			credential.Username = val
		}

		if keyIsURL(key) {
			credential.URL = val
		}

		if credential.Username != "" && credential.URL != "" {
			break
		}
	}

	return credential, err
}

func keyIsURL(k string) bool {
	return strings.EqualFold(k, "url")
}

func keyIsUsername(k string) bool {
	return strings.EqualFold(k, "username")
}
