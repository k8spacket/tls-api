package model

type RecordLayer struct {
	HandshakeType uint8
	TLSVersion    uint16
	Length        uint16
}

type HandshakeProtocol struct {
	HandshakeType uint8
	Length        [3]byte
	TLSVersion    uint16
	Random        [32]byte
}

type Session struct {
	Length uint8
	Id     []byte
}

type Ciphers struct {
	Length uint16
	Value  []byte
}

type CipherSuite struct {
	Value uint16
}

type CompressionMethods struct {
	Length uint8
	Value  []byte
}

type Extension struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type Extensions struct {
	Length     uint16
	Extensions map[uint16]Extension
}

type ServerNameExtension struct {
	ListLength uint16
	Type       uint8
	Length     uint16
	Value      []byte
}

const (
	TLSRecord byte = 0x16

	ClientHelloTLSRecord byte = 0x01
	ServerHelloTLSRecord byte = 0x02

	ServerNameExt uint16 = 0x00
	TLSVersionExt uint16 = 0x2b
)

var tlsVersions = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

func GetTLSVersion(version uint16) string {
	return tlsVersions[version]
}
