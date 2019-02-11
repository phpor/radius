package main
import (
	"fmt"
	"crypto"
	_ "crypto/md5"
	"bytes"
)


type Person struct {
	name string
	age int8
}
func main() {
//	pwd := []byte{144, 82, 51, 199, 237, 79, 249, 116, 206, 83, 43, 193, 157, 86, 217, 99, 89, 38, 90, 187, 50, 99, 5, 174, 137, 5, 160, 239, 170, 125, 153, 57}
//	authenticator := []byte{102, 163, 184, 212, 189, 184, 114, 210, 223, 255, 92, 15, 195, 149, 98, 186}
//	decodeUserPassword(pwd, authenticator)
	fmt.Println([]byte{1,2,3}[0:3])
	fmt.Printf("%v", &Person{"junjie", 18})
}

func decodeUserPassword(pass , authenticator []byte)(error){
	// todo: 密码超过16位时的解密方法： http://www.untruth.org/~josh/security/radius/radius-auth.html
	//Decode password. XOR against md5(p.server.secret+Authenticator)
	sec := append([]byte(nil), []byte("sEcReT")...)

	md := md5(append(sec, authenticator...))

	lenPass := len(pass)
	var block [16]byte
	var pwd []byte
	for j := 0; j < lenPass/16;j++ {
		s := j*16
		fmt.Println("md:", md)
		for i := 0;i < 16;i++ {
			block[i] = pass[s+i] ^ md[i]
		}
		pwd = append(pwd, block[:]...)
		md = md5(append(sec, pass[s:s+16]...))
	}
	fmt.Println(pwd)
	println(string( bytes.TrimRight(pwd, string([]rune{0}))))

	return nil
}
func md5(s []byte) []byte{
	m := crypto.Hash(crypto.MD5).New()
	m.Write(s)
	return m.Sum(nil)
}