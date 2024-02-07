package secrets

import (
	"log"

	"github.com/godbus/dbus/v5"
	keyring "github.com/ppacher/go-dbus-keyring"
)

func logError(err error) string {
	if err != nil {
		log.Print(err)
	}
	return ""
}

func GetSecret(label string) string {
	conn, err := dbus.SessionBus()
	if err != nil {
		return logError(err)
	}

	svc, err := keyring.GetSecretService(conn)
	if err != nil {
		return logError(err)
	}

	// session is required to create/retrieve secrets
	session, err := svc.OpenSession()
	if err != nil {
		return logError(err)
	}
	defer func() {
		err := session.Close()
		if err != nil {
			logError(err)
		}
	}()

	search := map[string]string{}

	search["Title"] = label

	unlocked, locked, err := svc.SearchItems(search)
	if err != nil {
		return logError(err)
	}

	for _, tg := range unlocked {
		s, err := tg.GetSecret(session.Path())
		if err != nil {
			return logError(err)
		}
		return string(s.Value)
	}

	for _, tg := range locked {
		tg.Unlock()

		s, err := tg.GetSecret(session.Path())
		if err != nil {
			return logError(err)
		}
		return string(s.Value)
	}

	return ""
}

