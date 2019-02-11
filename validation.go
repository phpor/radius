package radius

import (
	"bytes"
"crypto"
	_ "crypto/md5"
	"errors"
	"time"
	"net"
)
type AttributeDataType uint8
const (
	_ = iota
	TEXT AttributeDataType= iota
	STRING AttributeDataType= iota
	ADDRESS AttributeDataType= iota
	VALUE AttributeDataType=  iota
	INTEGER AttributeDataType=  iota
	TIME AttributeDataType=  iota
)

const (
	UNLIMITED = -1
)
type Validation struct {
	Kind AttributeDataType
	MinLength int 
	MaxLength int //if < 0 unlimited 
	Decode func(p *Packet, attr *AVP)(error)
}
func (a AVP) Binary()([]byte, error) {return a.Value,nil}
func (a AVP) Address()(net.Addr , error) {return nil,nil}
func (a AVP) Integer()(uint32, error) {return 0,nil}
func (a AVP) Time()(time.Time,error) {return time.Time{},nil}
func (a AVP) Text()(string,error) {return "",nil}

func (v Validation) Validate(p *Packet,attr *AVP)(error){

	if len(attr.Value) < v.MinLength {
			return errors.New("value too short")
	}

	if v.MaxLength != UNLIMITED &&  len(attr.Value) > v.MaxLength {
			return errors.New("value too long")		
	}

	switch v.Kind {
	case TEXT :
	case STRING :
	case ADDRESS:
	case VALUE:
	case INTEGER :
	case TIME:
	}

	if v.Decode != nil {
		return v.Decode(p,attr)
	}
	return nil
}

func DecodeUserPassword(p *Packet, a *AVP)(error){
	// todo: 密码超过16位时的解密方法： http://www.untruth.org/~josh/security/radius/radius-auth.html
	//Decode password. XOR against md5(p.server.secret+Authenticator)
		sec := append([]byte(nil), []byte(p.server.secret)...)

		md := md5(append(sec, p.Authenticator[:]...))
		ps := p.Attributes(UserPassword)
		pass := ps[0].Value
		lenPass := len(pass)
		var block [16]byte
		var pwd []byte
		for j := 0; j < lenPass/16;j++ {
			s := j*16
			for i := 0;i < 16;i++ {
				block[i] = pass[s+i] ^ md[i]
			}
			pwd = append(pwd, block[:]...)
			sec = append([]byte(nil), sec...)
			md = md5(append(sec, pass[s:s+16]...))
		}
		a.Value = bytes.TrimRight(pwd, string([]rune{0}))

		return nil
}
func md5(s []byte) []byte{
	m := crypto.Hash(crypto.MD5).New()
	m.Write(s)
	return m.Sum(nil)
}
var validation  = map[AttributeType]Validation {
	UserName: {STRING,1,UNLIMITED,nil},
	UserPassword           :{STRING,16,128,DecodeUserPassword},
	CHAPPassword           :{STRING,17,17,nil},
	NASIPAddress           : {ADDRESS,4,4,nil},
	NASPort : {VALUE,4,4,nil},
	ServiceType            :{},
	FramedProtocol         :{},
	FramedIPAddress        :{},
	FramedIPNetmask        :{},
	FramedRouting          :{},
	FilterId:{},
	FramedMTU              :{},
	FramedCompression      :{},
	LoginIPHost            :{},
	LoginService           :{},
	LoginTCPPort           :{},
	ReplyMessage           :{},
	CallbackNumber         :{},
	CallbackId             :{},
	FramedRoute            :{},
	FramedIPXNetwork       :{},
	State   :{},
	Class   :{},
	VendorSpecific         :{},
	SessionTimeout         :{},
	IdleTimeout            :{},
	TerminationAction      :{},
	CalledStationId        :{},
	CallingStationId       :{},
	NASIdentifier          :{},
	ProxyState             :{},
	LoginLATService        :{},
	LoginLATNode           :{},
	LoginLATGroup          :{},
	FramedAppleTalkLink    :{},
	FramedAppleTalkNetwork :{},
	FramedAppleTalkZone    :{},
	AcctStatusType         :{},
	AcctDelayTime          :{},
	AcctInputOctets        :{},
	AcctOutputOctets       :{},
	AcctSessionId          :{},
	AcctAuthentic          :{},
	AcctSessionTime        :{},
	AcctInputPackets       :{},
	AcctOutputPackets      :{},
	AcctTerminateCause     :{},
	AcctMultiSessionId     :{},
	AcctLinkCount          :{},

	CHAPChallenge :{},
	NASPortType   :{},
	PortLimit    :{},
	LoginLATPort  :{},
}


/*
AccessRequest      PacketCode = 1
MUST NAS-IP-Address AND/OR NAS-Identifier

     User-Password XOR CHAP-Password XOR State XOR someother authentication





AccessAccept       PacketCode = 2
AccessReject       PacketCode = 3


AccountingRequest  PacketCode = 4
AccountingResponse PacketCode = 5
AccessChallenge    PacketCode = 11

*/