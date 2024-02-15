module github.com/defektive/secrets

go 1.21.1

replace github.com/ppacher/go-dbus-keyring v1.0.1 => github.com/defektive/go-dbus-keyring v0.0.0-20230720125223-e70b0c2c1691

require (
	github.com/godbus/dbus/v5 v5.1.0
	github.com/ppacher/go-dbus-keyring v1.0.1
)
