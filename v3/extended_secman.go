package ldap

import (
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type ExtendedRequest struct {
	// OperationOID идентификатор расширенной операции
	OperationOID string
	// OperationName название операции
	OperationName string
	// Controls управляющие последовательности
	Controls []Control
}

func encodeExtendedControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "Control Extended data")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}

// appendTo формирует запрос и добавляет его к указанному пакету
func (ext *ExtendedRequest) appendTo(envelope *ber.Packet) error {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, ext.OperationName+" Extended Operation")
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, ext.OperationOID, ext.OperationName+" Extended Request"))

	if len(ext.Controls) > 0 {
		req.AppendChild(encodeExtendedControls(ext.Controls))
	}

	envelope.AppendChild(req)
	return nil
}

func (l *Conn) Extended(extendedRequest *ExtendedRequest) (*ber.Packet, error) {
	msgCtx, err := l.doRequest(extendedRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	l.Debug.Printf("%d: waiting for response", msgCtx.id)

	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err := packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if packet == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationExtendedResponse {
		if err := GetLDAPError(packet); err != nil {
			return nil, err
		}
	} else {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("unexpected response: %d", packet.Children[1].Tag))
	}

	return packet, nil
}
