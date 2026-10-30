package dice

import (
	"context"
	"errors"
	"fmt"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/dice/service"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// errMissingCharIDOrName reports a character request that named neither an id
// nor a name, matching the legacy protocol sentinel.
var errMissingCharIDOrName = errors.New("missing id or name")

// CharacterService is the Core-owned implementation of the provider character
// API. It owns durable character state and enforces the legacy ownership and
// platform rules; provider runtimes relay bounded DTOs and apply their own
// per-endpoint write rate limit.
type CharacterService struct {
	dice *Dice
}

func NewCharacterService(instance *Dice) *CharacterService {
	return &CharacterService{dice: instance}
}

var _ endpoint.CharacterSink = (*CharacterService)(nil)

// HandleCharacter executes one fenced character operation. Malformed requests
// produce an explicit failure response so the provider is not left waiting.
func (svc *CharacterService) HandleCharacter(ctx context.Context, request endpoint.FencedCharacterRequest) (adapterapi.CharacterResponse, error) {
	if svc == nil || svc.dice == nil || svc.dice.AttrsManager == nil {
		return adapterapi.CharacterResponse{OK: false, Error: "character service is unavailable"}, nil
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.CharacterResponse{}, err
	}
	attrs := svc.attrs()
	attrs.callbackGate.Lock()
	defer attrs.callbackGate.Unlock()
	if err := ctx.Err(); err != nil {
		return adapterapi.CharacterResponse{}, err
	}
	operation := request.Request
	switch operation.Operation {
	case adapterapi.CharacterOperationGet:
		return svc.get(operation), nil
	case adapterapi.CharacterOperationSet:
		return svc.set(operation), nil
	case adapterapi.CharacterOperationList:
		return svc.list(operation), nil
	case adapterapi.CharacterOperationNew:
		return svc.newCharacter(operation), nil
	case adapterapi.CharacterOperationSave:
		return svc.save(operation), nil
	case adapterapi.CharacterOperationTag:
		return svc.tag(operation), nil
	case adapterapi.CharacterOperationUntagAll:
		return svc.untagAll(operation), nil
	case adapterapi.CharacterOperationLoad:
		return svc.load(operation), nil
	case adapterapi.CharacterOperationDelete:
		return svc.delete(operation), nil
	default:
		return adapterapi.CharacterResponse{OK: false, Error: "unsupported character operation"}, nil
	}
}

func (svc *CharacterService) failure(err error) adapterapi.CharacterResponse {
	return adapterapi.CharacterResponse{OK: false, Error: err.Error()}
}

func (svc *CharacterService) attrs() *AttrsManager { return svc.dice.AttrsManager }

// characterMetadata reads the durable owner/type/name facts for a character
// without loading its payload. In the event-sourced runtime the legacy SQL
// operator is unset, so the projection is the source of truth; the legacy path
// is retained only for the SQL-backed runtime.
func (svc *CharacterService) characterMetadata(id string) (owner, attrsType, name, sheetType string, exists bool, err error) {
	manager := svc.attrs()
	if manager.durable != nil {
		state, readErr := attributestate.ReadProjected(context.Background(), manager.store, manager.diceID, id)
		if errors.Is(readErr, eventstore.ErrNotFound) {
			return "", "", "", "", false, nil
		}
		if readErr != nil {
			return "", "", "", "", false, readErr
		}
		if state.AttrsType == "" {
			return "", "", "", "", false, nil
		}
		return state.OwnerID, state.AttrsType, state.Name, state.SheetType, true, nil
	}
	item, readErr := service.AttrsGetById(manager.db, id)
	if readErr != nil {
		return "", "", "", "", false, readErr
	}
	if !item.IsDataExists() {
		return "", "", "", "", false, nil
	}
	return item.OwnerId, item.AttrsType, item.Name, item.SheetType, true, nil
}

// commitAttributes durably persists a mutated attribute item and reports any
// write error so success is never claimed before the state is committed.
func (svc *CharacterService) commitAttributes(item *AttributesItem) error {
	if item == nil {
		return errors.New("character item is unavailable")
	}
	manager := svc.attrs()
	if manager.durable != nil {
		return manager.saveItem(item)
	}
	if manager.db == nil {
		return errors.New("character storage is unavailable")
	}
	model, err := item.GetBatchSaveModel()
	if err != nil {
		return err
	}
	return service.AttrsPutsByIDBatch(manager.db, []*service.AttributesBatchUpsertModel{model})
}

func (svc *CharacterService) get(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	userID := FormatDiceIDSealChat(request.UserID)
	attrs, err := svc.attrs().Load(groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	data := make(map[string]any)
	attrs.Range(func(key string, value *ds.VMValue) bool {
		data[key] = vmValueToAny(value)
		return true
	})
	return adapterapi.CharacterResponse{OK: true, Attributes: data, AttributesSet: true, Name: attrs.Name, SheetType: attrs.SheetType}
}

func (svc *CharacterService) set(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	if request.Attributes == nil && (!request.NameSet || request.Name == "") {
		return adapterapi.CharacterResponse{OK: false, Error: "missing attrs or name"}
	}
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	userID := FormatDiceIDSealChat(request.UserID)
	attrs, err := svc.attrs().Load(groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	for key, value := range request.Attributes {
		attrs.Store(key, anyToVMValue(value))
	}
	if request.NameSet && request.Name != "" {
		attrs.Name = request.Name
		attrs.SetModified()
	}
	if err := svc.commitAttributes(attrs); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true}
}

func (svc *CharacterService) list(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	list, err := svc.attrs().GetCharacterList(FormatDiceIDSealChat(request.UserID))
	if err != nil {
		return svc.failure(err)
	}
	result := make([]adapterapi.CharacterSummary, 0, len(list))
	for _, item := range list {
		result = append(result, adapterapi.CharacterSummary{ID: item.Id, Name: item.Name, SheetType: item.SheetType, UpdatedAt: item.UpdatedAt})
	}
	return adapterapi.CharacterResponse{OK: true, List: result}
}

func (svc *CharacterService) newCharacter(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" || !request.NameSet || request.Name == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id, user_id or name"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	if svc.attrs().CharCheckExists(userID, request.Name) {
		return adapterapi.CharacterResponse{OK: false, Error: "character already exists"}
	}
	sheetType := request.SheetType
	if sheetType == "" {
		sheetType = "coc7"
	}
	item, err := svc.attrs().CharNew(userID, request.Name, sheetType)
	if err != nil {
		return svc.failure(err)
	}
	if err := svc.attrs().CharBind(item.Id, groupID, userID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: item.Id, Name: request.Name, SheetType: sheetType, BoundGroupID: groupID}
}

func (svc *CharacterService) save(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)

	current, err := svc.attrs().Load(groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	name := request.Name
	if name == "" {
		name = current.Name
	}
	if name == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "name is required"}
	}
	sheetType := request.SheetType
	if sheetType == "" {
		sheetType = current.SheetType
	}
	if sheetType == "" {
		sheetType = "coc7"
	}

	var action string
	var charID string
	existingID, _ := svc.attrs().CharIdGetByName(userID, name)
	if existingID == "" {
		newItem, err := svc.attrs().CharNew(userID, name, sheetType)
		if err != nil {
			return svc.failure(err)
		}
		charID = newItem.Id
		action = "created"
		newAttrs, err := svc.attrs().LoadById(charID)
		if err != nil {
			return svc.failure(err)
		}
		current.Range(func(key string, value *ds.VMValue) bool {
			newAttrs.Store(key, value)
			return true
		})
		newAttrs.Name = name
		newAttrs.SheetType = sheetType
		if err := svc.commitAttributes(newAttrs); err != nil {
			return svc.failure(err)
		}
	} else {
		bindingGroups := svc.attrs().CharGetBindingGroupIdList(existingID)
		if len(bindingGroups) > 0 {
			return adapterapi.CharacterResponse{OK: false, Error: "character is bound, cannot overwrite", UnboundGroups: bindingGroups}
		}
		charID = existingID
		action = "updated"
		existingAttrs, err := svc.attrs().LoadById(charID)
		if err != nil {
			return svc.failure(err)
		}
		existingAttrs.Clear()
		current.Range(func(key string, value *ds.VMValue) bool {
			existingAttrs.Store(key, value)
			return true
		})
		existingAttrs.Name = name
		existingAttrs.SheetType = sheetType
		existingAttrs.SetModified()
		if err := svc.commitAttributes(existingAttrs); err != nil {
			return svc.failure(err)
		}
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: name, Action: action}
}

func (svc *CharacterService) tag(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)

	charID, charName, err := svc.charIDFromRequest(request, userID)
	if err != nil && !errors.Is(err, errMissingCharIDOrName) {
		return svc.failure(err)
	}
	if charID != "" {
		if err := svc.attrs().CharBind(charID, groupID, userID); err != nil {
			return svc.failure(err)
		}
		return adapterapi.CharacterResponse{OK: true, Action: "bind", ID: charID, Name: charName}
	}
	currentBindingID, _ := svc.attrs().CharGetBindingId(groupID, userID)
	if currentBindingID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "no character bound"}
	}
	var unboundName string
	if currentAttrs, err := svc.attrs().LoadById(currentBindingID); err == nil && currentAttrs != nil {
		unboundName = currentAttrs.Name
	}
	if err := svc.attrs().CharBind("", groupID, userID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, Action: "unbind", ID: currentBindingID, Name: unboundName}
}

func (svc *CharacterService) untagAll(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	charID, charName, err := svc.charIDFromRequest(request, userID)
	if errors.Is(err, errMissingCharIDOrName) {
		if request.GroupID != "" {
			groupID := FormatDiceIDSealChatGroup(request.GroupID)
			charID, _ = svc.attrs().CharGetBindingId(groupID, userID)
			if charID != "" {
				if attrs, err := svc.attrs().LoadById(charID); err == nil && attrs != nil {
					charName = attrs.Name
				}
			}
		}
	} else if err != nil {
		return svc.failure(err)
	}
	if charID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "no character specified or bound"}
	}
	unbound := svc.attrs().CharUnbindAll(charID)
	if unbound == nil {
		return svc.failure(errors.New("character unbind failed"))
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName, UnboundGroups: unbound}
}

func (svc *CharacterService) load(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)

	charID, charName, err := svc.charIDFromRequest(request, userID)
	if err != nil {
		return svc.failure(err)
	}
	source, err := svc.attrs().LoadById(charID)
	if err != nil {
		return svc.failure(err)
	}
	// Snapshot the source first: Load(groupID, userID) returns the bound card,
	// which can be the same item as source, so clearing the target before
	// copying would erase the data we are about to write.
	snapshot := make(map[string]*ds.VMValue)
	source.Range(func(key string, value *ds.VMValue) bool {
		snapshot[key] = value
		return true
	})
	sourceName, sourceSheet := source.Name, source.SheetType

	target, err := svc.attrs().Load(groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	target.Clear()
	for key, value := range snapshot {
		target.Store(key, value)
	}
	target.Name = sourceName
	target.SheetType = sourceSheet
	target.SetModified()
	if err := svc.commitAttributes(target); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName, SheetType: sourceSheet}
}

func (svc *CharacterService) delete(request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	charID, charName, err := svc.charIDFromRequest(request, userID)
	if err != nil {
		return svc.failure(err)
	}
	bindingGroups := svc.attrs().CharGetBindingGroupIdList(charID)
	if len(bindingGroups) > 0 {
		return adapterapi.CharacterResponse{OK: false, Error: "character is bound, use untagAll first", UnboundGroups: bindingGroups}
	}
	if err := svc.attrs().CharDelete(charID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName}
}

// charIDFromRequest resolves the target character by explicit id or, failing
// that, by name, enforcing the legacy ownership and type checks. It reads
// durable metadata so it works when the runtime has no SQL database handle.
func (svc *CharacterService) charIDFromRequest(request adapterapi.CharacterRequest, formattedUserID string) (string, string, error) {
	if request.Character != "" {
		owner, attrsType, name, _, exists, err := svc.characterMetadata(request.Character)
		if err != nil {
			return "", "", err
		}
		if !exists {
			return "", "", fmt.Errorf("character not found: %s", request.Character)
		}
		if owner != formattedUserID || attrsType != service.AttrsTypeCharacter {
			return "", "", errors.New("character not owned by user or invalid type")
		}
		return request.Character, name, nil
	}
	if request.NameSet && request.Name != "" {
		charID, err := svc.attrs().CharIdGetByName(formattedUserID, request.Name)
		if err != nil {
			return "", "", err
		}
		if charID == "" {
			return "", "", fmt.Errorf("character not found: %s", request.Name)
		}
		return charID, request.Name, nil
	}
	return "", "", errMissingCharIDOrName
}

// vmValueToAny converts a dicescript value into a JSON-serializable value.
func vmValueToAny(value *ds.VMValue) any {
	if value == nil {
		return nil
	}
	switch value.TypeId {
	case ds.VMTypeInt:
		return value.MustReadInt()
	case ds.VMTypeFloat:
		return value.MustReadFloat()
	case ds.VMTypeString:
		text, _ := value.ReadString()
		return text
	default:
		return value.ToString()
	}
}

// anyToVMValue converts a decoded JSON value into a dicescript value.
func anyToVMValue(value any) *ds.VMValue {
	switch typed := value.(type) {
	case float64:
		if typed == float64(int64(typed)) {
			return ds.NewIntVal(ds.IntType(typed))
		}
		return ds.NewFloatVal(typed)
	case int:
		return ds.NewIntVal(ds.IntType(typed))
	case int64:
		return ds.NewIntVal(ds.IntType(typed))
	case string:
		return ds.NewStrVal(typed)
	case bool:
		if typed {
			return ds.NewIntVal(1)
		}
		return ds.NewIntVal(0)
	case nil:
		return ds.NewStrVal("")
	default:
		return ds.NewStrVal(fmt.Sprintf("%v", value))
	}
}
