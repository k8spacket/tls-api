package tls_api

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
	"reflect"
)

func ParseTLSPayload(payload []byte) model.TLSWrapper {
	reader := bufio.NewReader(bytes.NewReader(payload))
	var tlsWrapper = model.TLSWrapper{}
	tlsWrapper = parseTLSRecord(reader, tlsWrapper)
	return tlsWrapper
}

func parseTLSRecord(reader *bufio.Reader, tlsWrapper model.TLSWrapper) model.TLSWrapper {
	var b, _ = reader.Peek(1)
	var recordLayer = model.RecordLayer{}
	if b[0] == model.TLSRecord {
		binary.Read(reader, binary.BigEndian, &recordLayer)
	}
	b, _ = reader.Peek(1)
	if b[0] == model.ClientHelloTLS {
		tlsWrapper.ClientHelloTLSRecord = parseClientHelloTLSRecord(reader)
	} else if b[0] == model.ServerHelloTLS {
		tlsWrapper.ServerHelloTLSRecord = parseServerHelloTLSRecord(reader)
	} else if b[0] == model.CertificateTLS {
		tlsWrapper.CertificateTLSRecord = parseCertificateTLSRecord(reader)
	} else {
		if !reflect.DeepEqual(recordLayer, model.RecordLayer{}) {
			parseAnotherTLSRecord(reader, recordLayer.Length)
		} else {
			parseAnotherTLSHandshakeProtocol(reader)
		}
	}
	var _, err = reader.Peek(1)
	if err == nil {
		tlsWrapper = parseTLSRecord(reader, tlsWrapper)
	}
	return tlsWrapper
}

func parseAnotherTLSRecord(reader *bufio.Reader, length uint16) {
	bytes := make([]byte, int(length))
	binary.Read(reader, binary.BigEndian, &bytes)
}

func parseAnotherTLSHandshakeProtocol(reader *bufio.Reader) {
	var handshakeType uint8
	var length [3]byte
	binary.Read(reader, binary.BigEndian, &handshakeType)
	binary.Read(reader, binary.BigEndian, &length)
	bytes := make([]byte, bytesToInt(length))
	binary.Read(reader, binary.BigEndian, &bytes)
}
