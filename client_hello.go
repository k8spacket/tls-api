package tls_api

import (
	"bytes"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
)

type ClientHelloTLSRecord struct {
	RecordLayer        model.RecordLayer
	HandshakeProtocol  model.HandshakeProtocol
	Session            model.Session
	Ciphers            model.Ciphers
	CompressionMethods model.CompressionMethods
	Extensions         model.Extensions
}

func parseClientHelloTLSRecord(payload []byte) ClientHelloTLSRecord {
	var tlsRecord ClientHelloTLSRecord

	reader := bytes.NewReader(payload)

	binary.Read(reader, binary.BigEndian, &tlsRecord.RecordLayer)
	binary.Read(reader, binary.BigEndian, &tlsRecord.HandshakeProtocol)

	binary.Read(reader, binary.BigEndian, &tlsRecord.Session.Length)
	sessionId := make([]byte, tlsRecord.Session.Length)
	binary.Read(reader, binary.BigEndian, &sessionId)
	tlsRecord.Session.Id = sessionId

	binary.Read(reader, binary.BigEndian, &tlsRecord.Ciphers.Length)
	ciphersValue := make([]byte, tlsRecord.Ciphers.Length)
	binary.Read(reader, binary.BigEndian, &ciphersValue)
	tlsRecord.Ciphers.Value = ciphersValue

	binary.Read(reader, binary.BigEndian, &tlsRecord.CompressionMethods.Length)
	compressionMethodsValue := make([]byte, tlsRecord.CompressionMethods.Length)
	binary.Read(reader, binary.BigEndian, &compressionMethodsValue)
	tlsRecord.CompressionMethods.Value = compressionMethodsValue

	binary.Read(reader, binary.BigEndian, &tlsRecord.Extensions.Length)

	tlsRecord.Extensions.Extensions = make(map[uint16]model.Extension)
	for reader.Len() > 0 {
		var extension model.Extension
		binary.Read(reader, binary.BigEndian, &extension.Type)
		binary.Read(reader, binary.BigEndian, &extension.Length)
		extensionValue := make([]byte, extension.Length)
		binary.Read(reader, binary.BigEndian, &extensionValue)
		extension.Value = extensionValue
		tlsRecord.Extensions.Extensions[extension.Type] = extension
	}

	return tlsRecord
}
