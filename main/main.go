package main

import (
	"github.com/phpor/radius"
	"log"
)

func main() {
	s := radius.NewServer(":1812", "sEcReT")
	s.RegisterService("auth", &radius.PasswordService{})
	log.Println("waiting for packets...")
	err := s.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}
