package radius

import (
	"errors"
	"fmt"
	"net/http"
	"io/ioutil"
	"strings"
)

func Authenticate(user, pass string) error {

	ip := "123.123.123.123"
	url := "http://sa.beebank.com/api/check"
	contenttype := "application/x-www-form-urlencoded"
	data := fmt.Sprintf("username=%s&password=%s&app=baoleiji&ip=%s", user, pass, ip)
	println(data)
	res, err := http.Post(url, contenttype, strings.NewReader(data))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	if string(body[11:18]) != "2000000" {
		return errors.New("bad username or password")
	}
	return nil
}
