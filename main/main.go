package main

import (
	"github.com/phpor/radius"
	"log"
	"fmt"
)

func main() {
	for{
		myserver()
	}
}

func myserver() {

	s := radius.NewServer(":1812", "12345")
	defer func() {     //必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			fmt.Println(err)    //这里的err其实就是panic传入的内容，55
		}

	}()
	s.RegisterService("auth", &radius.PasswordService{})
	log.Println("waiting for packets...")
	err := s.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}
