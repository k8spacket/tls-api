package tls_api

import (
	"bytes"
	"encoding/binary"
	"github.com/k8spacket/tls-api/model"
)

func parseClientHelloTLSRecord(payload []byte) model.ClientHelloTLSRecord {
	var tlsRecord model.ClientHelloTLSRecord

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

	tlsRecord.ResolvedClientFields.ServerName = getServerName(tlsRecord.Extensions).Value
	tlsRecord.ResolvedClientFields.SupportedVersions = getSupportedVersions(tlsRecord.Extensions).Value
	tlsRecord.ResolvedClientFields.Ciphers = getCiphers(tlsRecord.Ciphers)

	return tlsRecord
}

func getServerName(record model.Extensions) model.ServerNameExtension {
	extension := record.Extensions[model.ServerNameExt]

	var serverNameExtension model.ServerNameExtension

	reader := bytes.NewReader(extension.Value)
	binary.Read(reader, binary.BigEndian, &serverNameExtension.ListLength)
	binary.Read(reader, binary.BigEndian, &serverNameExtension.Type)
	binary.Read(reader, binary.BigEndian, &serverNameExtension.Length)
	serverNameValue := make([]byte, serverNameExtension.Length)
	binary.Read(reader, binary.BigEndian, &serverNameValue)
	serverNameExtension.Value = string(serverNameValue)

	return serverNameExtension
}

func getSupportedVersions(record model.Extensions) model.SupportedVersionsExtension {
	extension := record.Extensions[model.SupportedVersionsExt]

	var supportedVersionsExtension model.SupportedVersionsExtension

	reader := bytes.NewReader(extension.Value)
	binary.Read(reader, binary.BigEndian, &supportedVersionsExtension.SupportedVersionLength)
	print(supportedVersionsExtension.SupportedVersionLength)
	supportedVersionValue := make([]byte, 2)
	for i := 0; i < int(supportedVersionsExtension.SupportedVersionLength/2); i++ {
		binary.Read(reader, binary.BigEndian, &supportedVersionValue)
		supportedVersionsExtension.Value = append(supportedVersionsExtension.Value, model.GetTLSVersion(binary.BigEndian.Uint16(supportedVersionValue)))
	}

	return supportedVersionsExtension
}

func getCiphers(ciphers model.Ciphers) []string {
	reader := bytes.NewReader(ciphers.Value)
	cipherValue := make([]byte, 2)
	var result []string
	for i := 0; i < int(ciphers.Length/2); i++ {
		binary.Read(reader, binary.BigEndian, cipherValue)
		result = append(result, model.GetCipherSuite(binary.BigEndian.Uint16(cipherValue)))
	}
	return result
}
