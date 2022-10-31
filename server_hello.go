package tls_api

import (
	"bytes"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
)

type ServerHelloTLSRecord struct {
	RecordLayer        model.RecordLayer
	HandshakeProtocol  model.HandshakeProtocol
	Session            model.Session
	CipherSuite        model.CipherSuite
	CompressionMethods model.CompressionMethods
	Extensions         model.Extensions
}

func parseServerHelloTLSRecord(payload []byte) ServerHelloTLSRecord {
	var tlsRecord ServerHelloTLSRecord

	reader := bytes.NewReader(payload)

	binary.Read(reader, binary.BigEndian, &tlsRecord.RecordLayer)
	binary.Read(reader, binary.BigEndian, &tlsRecord.HandshakeProtocol)

	binary.Read(reader, binary.BigEndian, &tlsRecord.Session.Length)
	sessionId := make([]byte, tlsRecord.Session.Length)
	binary.Read(reader, binary.BigEndian, &sessionId)
	tlsRecord.Session.Id = sessionId

	binary.Read(reader, binary.BigEndian, &tlsRecord.CipherSuite.Value)

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
