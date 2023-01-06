package tls_api

import (
	"bufio"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
)

func parseServerHelloTLSRecord(reader *bufio.Reader) model.ServerHelloTLSRecord {
	var tlsRecord model.ServerHelloTLSRecord

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
	var lengthCounter = 0
	for int(tlsRecord.Extensions.Length)-lengthCounter > 0 {
		var extension model.Extension
		binary.Read(reader, binary.BigEndian, &extension.Type)
		binary.Read(reader, binary.BigEndian, &extension.Length)
		extensionValue := make([]byte, extension.Length)
		binary.Read(reader, binary.BigEndian, &extensionValue)
		extension.Value = extensionValue
		tlsRecord.Extensions.Extensions[extension.Type] = extension
		lengthCounter += int(extension.Length) + 4
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
	return model.GetCipherSuite(cipher.Value)
}
