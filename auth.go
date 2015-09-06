package radius

import (
	"errors"
)

func Authenticate(user, pass string) error {
	println(user)
	println(pass)
	if user == "bob" && pass == "hello" {
		return nil
	}
	return errors.New("bad username or password")
}
