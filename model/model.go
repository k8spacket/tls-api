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
	Value      string
}

type SupportedVersionExtension struct {
	Type  uint16
	Value []byte
}

type SupportedVersionsExtension struct {
	SupportedVersionLength uint8
	Value                  []string
}

type ClientCiphers struct {
	Ciphers []string
}

type ResolvedClientFields struct {
	ServerName        string
	SupportedVersions []string
	Ciphers           []string
}

type ClientHelloTLSRecord struct {
	RecordLayer          RecordLayer
	HandshakeProtocol    HandshakeProtocol
	Session              Session
	Ciphers              Ciphers
	CompressionMethods   CompressionMethods
	Extensions           Extensions
	ResolvedClientFields ResolvedClientFields
}

type ResolvedServerFields struct {
	SupportedVersion string
	Cipher           string
}

type ServerHelloTLSRecord struct {
	RecordLayer          RecordLayer
	HandshakeProtocol    HandshakeProtocol
	Session              Session
	CipherSuite          CipherSuite
	CompressionMethods   CompressionMethods
	Extensions           Extensions
	ResolvedServerFields ResolvedServerFields
}

const (
	TLSRecord byte = 0x16

	ClientHelloTLS byte = 0x01
	ServerHelloTLS byte = 0x02

	ServerNameExt        uint16 = 0x0000
	SupportedVersionsExt uint16 = 0x002b
	TLSVersionExt        uint16 = 0x002b
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
