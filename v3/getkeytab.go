package ldap

import (
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
	"strconv"
	"time"
)

const (
	SetKeytabOID = "2.16.840.1.113730.3.8.10.1"
	GetKeytabOID = "2.16.840.1.113730.3.8.10.5"
	RetKeytabOID = "2.16.840.1.113730.3.8.10.2"
)

var OperationTypeMap = map[string]string{
	SetKeytabOID: "Set Keytab",
	GetKeytabOID: "Get Keytab",
	RetKeytabOID: "Ret Keytab",
}

func OperationByOID(oid string) string {
	return OperationTypeMap[oid]
}

type GetKeytabRequest struct {
	Principal string
	Realm     string
}

func (g GetKeytabRequest) GetControlType() string {
	return "Set Keytab"
}

func (g GetKeytabRequest) String() string {
	return ""
}

func (g GetKeytabRequest) Encode() *ber.Packet {
	principal := g.Principal + "@" + g.Realm

	req := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "Control Value")
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Get Keytab Request")

	user := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Set principal")
	user.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, principal, "Principal: "+principal))

	packet.AppendChild(user)

	req.AppendChild(packet)

	return req
}

// ParseGetKeytabResponse производит парсинг пакета, получая оттуда kvno и список поддерживаемых типов кодирования
func ParseGetKeytabResponse(packet *ber.Packet) (uint32, map[string][]types.EncryptionKey, error) {

	// Получаем управляющую последовательность с ответом, выходим в случае ошибки
	control := responseFindParentControl(packet, responseFindControlByValue(packet, GetKeytabOID))
	if control == nil {
		return 0, nil, fmt.Errorf("invalid response: missing valid control: %s", GetKeytabOID)
	}
	if len(control.Children) < 2 {
		return 0, nil, errors.New("invalid response: missing payload")
	}

	// Из последовательности получаем данные, выходим в случае ошибки
	payload, err := ber.ReadPacket(control.Children[1].Data)
	if err != nil {
		return 0, nil, fmt.Errorf("fail parse payload: %w", err)
	}

	if len(payload.Children) != 1 || payload.Children[0] == nil || len(payload.Children[0].Children) != 2 {
		return 0, nil, errors.New("invalid payload header")
	}

	payload = payload.Children[0]
	if len(payload.Children) < 2 || payload.Children[0] == nil || payload.Children[1] == nil {
		return 0, nil, errors.New("invalid payload")
	}

	// Из данных получаем kvno, выходим если формат неверен
	kvno, ok := payload.Children[0].Value.(int64)
	if !ok || kvno < 0 {
		return 0, nil, errors.New("invalid kvno")
	}

	// Получаем из данных идентификаторы поддерживаемых типов кодирования
	enctypeList := map[string][]types.EncryptionKey{}
	for _, enctype := range payload.Children[1].Children {
		if enctype == nil || len(enctype.Children) != 2 {
			continue
		}

		rawEncId := responseFindControlByIdent(enctype.Children[0], ber.Identifier{ClassType: ber.ClassUniversal, TagType: ber.TypePrimitive, Tag: ber.TagInteger})
		rawEncValue := responseFindControlByIdent(enctype.Children[0], ber.Identifier{ClassType: ber.ClassUniversal, TagType: ber.TypePrimitive, Tag: ber.TagOctetString})
		rawUpn := responseFindControlByIdent(enctype.Children[1], ber.Identifier{ClassType: ber.ClassUniversal, TagType: ber.TypePrimitive, Tag: ber.TagOctetString})

		// Проверяем идентификатор шифрования
		encId, ok := rawEncId.Value.(int64)
		if !ok {
			continue
		}

		// Проверяем данные
		encValue, ok := rawEncValue.Value.(string)
		if !ok {
			continue
		}

		// Проверяем обратный SPN/UPN
		revertXpn, ok := rawUpn.Value.(string)
		if !ok {
			continue
		}
		if _, ok = enctypeList[revertXpn]; !ok {
			enctypeList[revertXpn] = nil
		}
		enctypeList[revertXpn] = append(enctypeList[revertXpn], types.EncryptionKey{
			KeyType:  int32(encId),
			KeyValue: []byte(encValue),
		})
	}

	// Если не было найдено ни одного ключа кодирования
	if len(enctypeList) == 0 {
		return 0, nil, errors.New("no enctype")
	}

	return uint32(kvno), enctypeList, nil
}

type SetKeytabRequest struct {
	Principal      string
	Realm          string
	EncryptionKeys map[int]types.EncryptionKey
}

func (s *SetKeytabRequest) GetControlType() string {
	return "Set Keytab"
}

func (s *SetKeytabRequest) String() string {
	return ""
}

func (s *SetKeytabRequest) Encode() *ber.Packet {
	// Получаем имя принципала
	principal := s.Principal + "@" + s.Realm
	principalCompact := s.Realm + s.Principal
	ETypesByName := swapMap(etypeID.ETypesByName)

	req := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Set Keytab Request")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, principal, "Principal: "+principal))

	encryptionList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Encryption List")
	for keyType, key := range s.EncryptionKeys {
		encryptionType := ETypesByName[key.KeyType]

		// Формируем заголовок и данные типа шифрования
		encryptionId := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Encryption: "+encryptionType)
		encryptionId.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, key.KeyType, "Encryption ID: "+strconv.Itoa(keyType)))
		encryptionData := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "Encryption Binary Sequence")
		encryptionData.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(key.KeyValue), "Encryption Binary Data"))
		encryption := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Encryption Sequence")
		encryption.AppendChild(encryptionId)
		encryption.AppendChild(encryptionData)
		controlEncryption := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Control Encryption: "+encryptionType)
		controlEncryption.AppendChild(encryption)

		// Формируем принципал для типа шифрования
		markerId := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "Marker Type")
		markerId.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Principal Marker"))
		markerData := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "Marker value")
		markerData.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, principalCompact, "Marker: "+principalCompact))
		marker := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Encryption Marker Sequence")
		marker.AppendChild(markerId)
		marker.AppendChild(markerData)
		controlMarker := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "Control Marker: "+principal)
		controlMarker.AppendChild(marker)

		// Формируем тип шифрования
		encryptionSequence := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Encryption Sequence Type: "+encryptionType)
		encryptionSequence.AppendChild(controlEncryption)
		encryptionSequence.AppendChild(controlMarker)

		// Добавляем его в список
		encryptionList.AppendChild(encryptionSequence)
	}
	req.AppendChild(encryptionList)
	return req
}

// ParseSetKeytabResponse производит парсинг пакета, получая оттуда kvno и список поддерживаемых типов кодирования
func ParseSetKeytabResponse(packet *ber.Packet) (uint32, []int, error) {

	// Получаем управляющую последовательность с ответом, выходим в случае ошибки
	control := responseFindParentControl(packet, responseFindControlByValue(packet, RetKeytabOID))
	if control == nil {
		return 0, nil, fmt.Errorf("invalid response: missing valid control: %s", RetKeytabOID)
	}
	if len(control.Children) < 2 {
		return 0, nil, errors.New("invalid response: missing payload")
	}

	// Из последовательности получаем данные, выходим в случае ошибки
	payload, err := ber.ReadPacket(control.Children[1].Data)
	if err != nil {
		return 0, nil, fmt.Errorf("fail parse payload: %w", err)
	}
	if len(payload.Children) < 2 || payload.Children[0] == nil || payload.Children[1] == nil {
		return 0, nil, errors.New("invalid payload")
	}

	// Из данных получаем kvno, выходим если формат неверен
	kvno, ok := payload.Children[0].Value.(int64)
	if !ok || kvno < 0 {
		return 0, nil, errors.New("invalid kvno")
	}

	// Получаем из данных идентификаторы поддерживаемых типов кодирования
	enctypeList := make([]int, 0)
	for _, enctype := range payload.Children[1].Children {
		if enctype == nil || len(enctype.Children) == 0 {
			continue
		}
		if enctypeId, ok := enctype.Children[0].Value.(int64); ok {
			enctypeList = append(enctypeList, int(enctypeId))
		}
	}

	// Если не было найдено ни одного поддерживаемого идентификатора кодирования
	if len(enctypeList) == 0 {
		return 0, nil, errors.New("no supported enctype")
	}

	return uint32(kvno), enctypeList, nil
}

type ExtendedQuery interface {
	Extended(extendedRequest *ExtendedRequest) (*ber.Packet, error)
}

type Keytab struct {
	conn            ExtendedQuery
	principal       types.PrincipalName
	realm           string
	password        string
	encryptionTypes []string
	encryptionKeys  map[int]types.EncryptionKey
}

func NewKeytabRequest(conn ExtendedQuery) *Keytab {
	return &Keytab{
		conn: conn,
	}
}

// SetConnection сохраняет соединение
func (k *Keytab) SetConnection(conn ExtendedQuery) *Keytab {
	k.conn = conn
	return k
}

// SetSPN устанавливает SPN
func (k *Keytab) SetSPN(spn string) *Keytab {
	k.principal, k.realm = types.ParseSPNString(spn)
	return k
}

// SetUPN устанавливает UPN
func (k *Keytab) SetUPN(upn string) *Keytab {
	k.principal, k.realm = types.ParseSPNString(upn)
	return k
}

// SetPassword устанавливает пароль
func (k *Keytab) SetPassword(password string) *Keytab {
	k.password = password
	return k
}

// SetEncryptionTypes устанавливает список типов кодировок
func (k *Keytab) SetEncryptionTypes(encryptionTypes []string) *Keytab {
	k.encryptionTypes = encryptionTypes
	return k
}

func (k *Keytab) NewExtendedRequest(operationOID string, controls []Control) *ExtendedRequest {
	return &ExtendedRequest{
		OperationOID:  operationOID,
		OperationName: OperationByOID(operationOID),
		Controls:      cloneSliceControl(controls),
	}
}

func (k *Keytab) GetKeytab(receiveOnly bool) (*keytab.Keytab, error) {
	var (
		kvno           uint32
		encList        []types.EncryptionKey
		encryptionKeys map[int]types.EncryptionKey
	)

	// Проверяем ошибки
	if len(k.principal.NameString) == 0 {
		return nil, errors.New("principal not set")
	}
	if k.realm == "" {
		return nil, errors.New("realm not set")
	}

	principalCompact := k.realm + k.principal.PrincipalNameString()

	// Формируем запрос на получение keytab
	req := k.NewExtendedRequest(GetKeytabOID, []Control{&GetKeytabRequest{
		Principal: k.principal.PrincipalNameString(),
		Realm:     k.realm,
	}})

	// Выполняем запрос, выходим в случае ошибки, исключая ошибку, связанную с недостаточными правами
	op, err := k.conn.Extended(req)
	if err != nil && !IsErrorWithCode(err, LDAPResultInsufficientAccessRights) {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("invalid response: %w", err))
	}

	// Обрабатываем ответ
	if err == nil {
		responseKvno, responseEncList, err := ParseGetKeytabResponse(op)
		if err != nil {
			return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("invalid response: %w", err))
		}

		// Фильтруем ключи шифрования, оставляя только поддерживаемые
		ETypesById := swapMap(etypeID.ETypesByName)
		for _, key := range responseEncList[principalCompact] {
			if _, ok := ETypesById[key.KeyType]; ok {
				encList = append(encList, key)
			}
		}
		kvno = responseKvno
	}

	// Если получить keytab не удалось и можно обновлять keytab, будем делать запрос на смену keytab, получение нового kvno и поддерживаемых типов шифрования.
	if (kvno == 0 || len(encList) == 0) && !receiveOnly {

		// Собираем информацию о требуемых типах шифрования, по-умолчанию будем использовать все поддерживаемые типы шифрования сразу
		encryptionTypes := cloneSliceString(k.encryptionTypes)
		if len(encryptionTypes) == 0 {
			for typeName := range etypeID.ETypesByName {
				encryptionTypes = append(encryptionTypes, typeName)
			}
		}

		// Формируем список поддерживаемых ключей шифрования
		encryptionKeys = map[int]types.EncryptionKey{}
		for _, encryptionType := range encryptionTypes {
			if etypeID.EtypeSupported(encryptionType) != 0 {
				if key, _, err := crypto.GetKeyFromPassword(k.password, k.principal, k.realm, etypeID.ETypesByName[encryptionType], types.PADataSequence{}); err == nil {
					encryptionKeys[int(key.KeyType)] = key
				}
			}
		}

		// Формируем запрос на смену keytab
		setKeytabCtrl := &SetKeytabRequest{
			Principal:      k.principal.PrincipalNameString(),
			Realm:          k.realm,
			EncryptionKeys: encryptionKeys,
		}

		// Выполняем запрос, выходим в случае ошибки
		req = k.NewExtendedRequest(SetKeytabOID, []Control{setKeytabCtrl})
		op, err = k.conn.Extended(req)
		if err != nil {
			return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("invalid response: %w", err))
		}

		// Производим парсинг ответа
		responseKvno, responseKeys, err := ParseSetKeytabResponse(op)
		if err != nil {
			return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("invalid response: %w", err))
		}
		for _, key := range responseKeys {
			encList = append(encList, encryptionKeys[key])
		}
		kvno = responseKvno
	}

	if len(encList) == 0 {
		return nil, NewError(ErrorUnexpectedResponse, errors.New("no supported encode types"))
	}

	if kvno == 0 {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("invalid kvno: %w", err))
	}

	// Генерируем keytab
	kt := keytab.New()
	if err = kt.AddEntriesByKeyList(k.principal.PrincipalNameString(), k.realm, time.Now(), kvno, encList); err != nil {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("fail create keytab: %w", err))
	}

	return kt, nil
}

// responseFindControlByValue находит и возвращает управляющую последовательность по её значению или nil, если последовательность не найдена
func responseFindControlByValue(packet *ber.Packet, value interface{}) *ber.Packet {
	if packet == nil || len(packet.Children) == 0 {
		return nil
	}
	for _, child := range packet.Children {
		if child.Value == value {
			return child
		}
	}
	for _, child := range packet.Children {
		if control := responseFindControlByValue(child, value); control != nil {
			return control
		}
	}
	return nil
}

// responseFindControlByIdent находит и возвращает управляющую последовательность по её идентификатору или nil, если последовательность не найдена
func responseFindControlByIdent(packet *ber.Packet, ident ber.Identifier) *ber.Packet {
	if packet == nil || len(packet.Children) == 0 {
		return nil
	}
	for _, child := range packet.Children {
		if child.Identifier.ClassType == ident.ClassType && child.Identifier.TagType == ident.TagType && child.Identifier.Tag == ident.Tag {
			return child
		}
	}
	for _, child := range packet.Children {
		if control := responseFindControlByIdent(child, ident); control != nil {
			return control
		}
	}
	return nil
}

// responseFindParentControl находит и возвращает родительскую управляющую последовательность или nil, если последовательность не найдена
func responseFindParentControl(packet *ber.Packet, search *ber.Packet) *ber.Packet {
	if packet == nil || len(packet.Children) == 0 {
		return nil
	}
	for _, child := range packet.Children {
		if child == search {
			return packet
		}
	}
	for _, child := range packet.Children {
		if control := responseFindParentControl(child, search); control != nil {
			return control
		}
	}
	return nil
}

// swapMap меняет местами значения ключей и значений в карте
func swapMap(in map[string]int32) map[int32]string {
	result := make(map[int32]string, len(in))
	for k, v := range in {
		result[v] = k
	}
	return result
}

// cloneSliceString клонирует слайс строк
func cloneSliceString(in []string) []string {
	result := make([]string, len(in))
	copy(result, in)
	return result
}

// cloneSliceControl клонирует слайс управляющих последовательностей
func cloneSliceControl(in []Control) []Control {
	result := make([]Control, len(in))
	copy(result, in)
	return result
}
