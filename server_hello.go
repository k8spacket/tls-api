package tls_api

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
)

func parseServerHelloTLSRecord(payload []byte) model.ServerHelloTLSRecord {
	var tlsRecord model.ServerHelloTLSRecord

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

	tlsRecord.ResolvedServerFields.SupportedVersion = getSupportedVersion(tlsRecord)
	tlsRecord.ResolvedServerFields.Cipher = getCipher(tlsRecord.CipherSuite)

	return tlsRecord
}

func getSupportedVersion(record model.ServerHelloTLSRecord) string {
	var version = model.GetTLSVersion(record.HandshakeProtocol.TLSVersion)
	extension := record.Extensions.Extensions[model.TLSVersionExt]
	if extension.Value != nil {
		version = model.GetTLSVersion(binary.BigEndian.Uint16(extension.Value))
	}
	return version
}

func getCipher(cipher model.CipherSuite) string {
	return tls.CipherSuiteName(cipher.Value)
}
