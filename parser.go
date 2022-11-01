package tls_api

import "github.com/k8spacket/tls-api/model"

func ParseTLSPayload(payload []byte) interface{} {
	if len(payload) > 5 && payload[0] == model.TLSRecord {
		if payload[5] == model.ClientHelloTLS {
			return parseClientHelloTLSRecord(payload)
		} else if payload[5] == model.ServerHelloTLS {
			return parseServerHelloTLSRecord(payload)
		}
	}
	return nil
}
