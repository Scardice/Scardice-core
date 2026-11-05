package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/endpoint"
)

var errMissingCharIDOrName = errors.New("missing id or name")

type CharacterService struct {
	dice *Dice
}

func NewCharacterService(instance *Dice) *CharacterService { return &CharacterService{dice: instance} }

var _ endpoint.CharacterSink = (*CharacterService)(nil)

// HandleCharacter owns one independent durable root. The fenced endpoint
// generation/version is the admission identity and the full request is the
// canonical digest input; every metadata/value read and write shares its one
// DomainTx.
func (svc *CharacterService) HandleCharacter(ctx context.Context, request endpoint.FencedCharacterRequest) (adapterapi.CharacterResponse, error) {
	if svc == nil || svc.dice == nil || svc.dice.AttrsManager == nil {
		return adapterapi.CharacterResponse{OK: false, Error: "character service is unavailable"}, nil
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.CharacterResponse{}, err
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return adapterapi.CharacterResponse{}, err
	}
	identity := fmt.Sprintf("character:%s:%d:%d", request.EndpointID, request.Generation, request.DesiredVersion)
	var response adapterapi.CharacterResponse
	err = svc.dice.WithDomainExecution(ctx, identity, canonical, func(tx *DurableCallbackTransaction) error {
		response = svc.execute(ctx, tx, request.Request)
		return nil
	})
	return response, err
}

func (svc *CharacterService) execute(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	switch request.Operation {
	case adapterapi.CharacterOperationGet:
		return svc.get(ctx, tx, request)
	case adapterapi.CharacterOperationSet:
		return svc.set(ctx, tx, request)
	case adapterapi.CharacterOperationList:
		return svc.list(ctx, tx, request)
	case adapterapi.CharacterOperationNew:
		return svc.newCharacter(ctx, tx, request)
	case adapterapi.CharacterOperationSave:
		return svc.save(ctx, tx, request)
	case adapterapi.CharacterOperationTag:
		return svc.tag(ctx, tx, request)
	case adapterapi.CharacterOperationUntagAll:
		return svc.untagAll(ctx, tx, request)
	case adapterapi.CharacterOperationLoad:
		return svc.load(ctx, tx, request)
	case adapterapi.CharacterOperationDelete:
		return svc.delete(ctx, tx, request)
	default:
		return adapterapi.CharacterResponse{OK: false, Error: "unsupported character operation"}
	}
}

func (svc *CharacterService) failure(err error) adapterapi.CharacterResponse {
	return adapterapi.CharacterResponse{OK: false, Error: err.Error()}
}

func (svc *CharacterService) attrs() *AttrsManager { return svc.dice.AttrsManager }

func (svc *CharacterService) characterMetadata(ctx context.Context, tx *DurableCallbackTransaction, id string) (attributestate.State, bool, error) {
	item, err := svc.attrs().LoadByTransaction(ctx, tx, id)
	if err != nil {
		return attributestate.State{}, false, err
	}
	state := item.State()
	if state.AttrsType == "" {
		return attributestate.State{}, false, nil
	}
	return state, true, nil
}

func (svc *CharacterService) get(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	userID := FormatDiceIDSealChat(request.UserID)
	attrs, err := svc.attrs().LoadForTransaction(ctx, tx, groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	data := make(map[string]any)
	attrs.Range(func(key string, value *ds.VMValue) bool {
		data[key] = vmValueToAny(value)
		return true
	})
	return adapterapi.CharacterResponse{
		OK: true, Attributes: data, AttributesSet: true, Name: attrs.Name(), SheetType: attrs.SheetType(),
	}
}

func (svc *CharacterService) set(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	if request.Attributes == nil && (!request.NameSet || request.Name == "") {
		return adapterapi.CharacterResponse{OK: false, Error: "missing attrs or name"}
	}
	attrs, err := svc.attrs().LoadForTransaction(ctx, tx, FormatDiceIDSealChatGroup(request.GroupID), FormatDiceIDSealChat(request.UserID))
	if err != nil {
		return svc.failure(err)
	}
	for key, value := range request.Attributes {
		if err = attrs.Store(key, anyToVMValue(value)); err != nil {
			return svc.failure(err)
		}
	}
	if request.NameSet && request.Name != "" {
		if err = attrs.SetName(request.Name); err != nil {
			return svc.failure(err)
		}
	}
	return adapterapi.CharacterResponse{OK: true}
}

func (svc *CharacterService) list(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	list, err := svc.attrs().GetCharacterListForTransaction(ctx, tx, FormatDiceIDSealChat(request.UserID))
	if err != nil {
		return svc.failure(err)
	}
	result := make([]adapterapi.CharacterSummary, 0, len(list))
	for _, item := range list {
		result = append(result, adapterapi.CharacterSummary{ID: item.Id, Name: item.Name, SheetType: item.SheetType, UpdatedAt: item.UpdatedAt})
	}
	return adapterapi.CharacterResponse{OK: true, List: result}
}

func (svc *CharacterService) newCharacter(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" || !request.NameSet || request.Name == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id, user_id or name"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	existingID, err := svc.attrs().CharIdGetByNameForTransaction(ctx, tx, userID, request.Name)
	if err != nil {
		return svc.failure(err)
	}
	if existingID != "" {
		return adapterapi.CharacterResponse{OK: false, Error: "character already exists"}
	}
	sheetType := request.SheetType
	if sheetType == "" {
		sheetType = "coc7"
	}
	item, err := svc.attrs().CharNewForTransaction(ctx, tx, userID, request.Name, sheetType)
	if err != nil {
		return svc.failure(err)
	}
	if err = svc.attrs().CharBindForTransaction(ctx, tx, item.Id, groupID, userID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: item.Id, Name: request.Name, SheetType: sheetType, BoundGroupID: groupID}
}

func (svc *CharacterService) save(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	current, err := svc.attrs().LoadForTransaction(ctx, tx, groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	name := request.Name
	if name == "" {
		name = current.Name()
	}
	if name == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "name is required"}
	}
	sheetType := request.SheetType
	if sheetType == "" {
		sheetType = current.SheetType()
	}
	if sheetType == "" {
		sheetType = "coc7"
	}

	existingID, err := svc.attrs().CharIdGetByNameForTransaction(ctx, tx, userID, name)
	if err != nil {
		return svc.failure(err)
	}
	var action, charID string
	if existingID == "" {
		newItem, createErr := svc.attrs().CharNewForTransaction(ctx, tx, userID, name, sheetType)
		if createErr != nil {
			return svc.failure(createErr)
		}
		charID, action = newItem.Id, "created"
	} else {
		bindingGroups, bindingErr := svc.attrs().CharGetBindingGroupIDListForTransaction(ctx, tx, existingID)
		if bindingErr != nil {
			return svc.failure(bindingErr)
		}
		if len(bindingGroups) > 0 {
			return adapterapi.CharacterResponse{OK: false, Error: "character is bound, cannot overwrite", UnboundGroups: bindingGroups}
		}
		charID, action = existingID, "updated"
	}
	target, err := svc.attrs().LoadByTransaction(ctx, tx, charID)
	if err != nil {
		return svc.failure(err)
	}
	target.Clear()
	var copyErr error
	current.Range(func(key string, value *ds.VMValue) bool {
		copyErr = target.Store(key, value)
		return copyErr == nil
	})
	if copyErr != nil {
		return svc.failure(copyErr)
	}
	if err = target.SetName(name); err != nil {
		return svc.failure(err)
	}
	if err = target.SetSheetType(sheetType); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: name, Action: action}
}

func (svc *CharacterService) tag(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	charID, charName, err := svc.charIDFromRequest(ctx, tx, request, userID)
	if err != nil && !errors.Is(err, errMissingCharIDOrName) {
		return svc.failure(err)
	}
	if charID != "" {
		if err = svc.attrs().CharBindForTransaction(ctx, tx, charID, groupID, userID); err != nil {
			return svc.failure(err)
		}
		return adapterapi.CharacterResponse{OK: true, Action: "bind", ID: charID, Name: charName}
	}
	currentBindingID, err := svc.attrs().CharGetBindingIDForTransaction(ctx, tx, groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	if currentBindingID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "no character bound"}
	}
	var unboundName string
	if currentAttrs, loadErr := svc.attrs().LoadByTransaction(ctx, tx, currentBindingID); loadErr == nil {
		unboundName = currentAttrs.Name()
	}
	if err = svc.attrs().CharBindForTransaction(ctx, tx, "", groupID, userID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, Action: "unbind", ID: currentBindingID, Name: unboundName}
}

func (svc *CharacterService) untagAll(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	charID, charName, err := svc.charIDFromRequest(ctx, tx, request, userID)
	if errors.Is(err, errMissingCharIDOrName) {
		if request.GroupID != "" {
			groupID := FormatDiceIDSealChatGroup(request.GroupID)
			charID, err = svc.attrs().CharGetBindingIDForTransaction(ctx, tx, groupID, userID)
			if err != nil {
				return svc.failure(err)
			}
			if charID != "" {
				if attrs, loadErr := svc.attrs().LoadByTransaction(ctx, tx, charID); loadErr == nil {
					charName = attrs.Name()
				}
			}
		}
	} else if err != nil {
		return svc.failure(err)
	}
	if charID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "no character specified or bound"}
	}
	unbound, err := svc.attrs().CharUnbindAllForTransaction(ctx, tx, charID)
	if err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName, UnboundGroups: unbound}
}

func (svc *CharacterService) load(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.GroupID == "" || request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing group_id or user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	groupID := FormatDiceIDSealChatGroup(request.GroupID)
	charID, charName, err := svc.charIDFromRequest(ctx, tx, request, userID)
	if err != nil {
		return svc.failure(err)
	}
	source, err := svc.attrs().LoadByTransaction(ctx, tx, charID)
	if err != nil {
		return svc.failure(err)
	}
	snapshot := make(map[string]*ds.VMValue)
	source.Range(func(key string, value *ds.VMValue) bool {
		snapshot[key] = value
		return true
	})
	sourceName, sourceSheet := source.Name(), source.SheetType()
	target, err := svc.attrs().LoadForTransaction(ctx, tx, groupID, userID)
	if err != nil {
		return svc.failure(err)
	}
	target.Clear()
	for key, value := range snapshot {
		if err = target.Store(key, value); err != nil {
			return svc.failure(err)
		}
	}
	if err = target.SetName(sourceName); err != nil {
		return svc.failure(err)
	}
	if err = target.SetSheetType(sourceSheet); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName, SheetType: sourceSheet}
}

func (svc *CharacterService) delete(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	if request.UserID == "" {
		return adapterapi.CharacterResponse{OK: false, Error: "missing user_id"}
	}
	userID := FormatDiceIDSealChat(request.UserID)
	charID, charName, err := svc.charIDFromRequest(ctx, tx, request, userID)
	if err != nil {
		return svc.failure(err)
	}
	bindingGroups, err := svc.attrs().CharGetBindingGroupIDListForTransaction(ctx, tx, charID)
	if err != nil {
		return svc.failure(err)
	}
	if len(bindingGroups) > 0 {
		return adapterapi.CharacterResponse{OK: false, Error: "character is bound, use untagAll first", UnboundGroups: bindingGroups}
	}
	if err = svc.attrs().CharDeleteForTransaction(ctx, tx, charID); err != nil {
		return svc.failure(err)
	}
	return adapterapi.CharacterResponse{OK: true, ID: charID, Name: charName}
}

func (svc *CharacterService) charIDFromRequest(ctx context.Context, tx *DurableCallbackTransaction, request adapterapi.CharacterRequest, formattedUserID string) (string, string, error) {
	if request.Character != "" {
		state, exists, err := svc.characterMetadata(ctx, tx, request.Character)
		if err != nil {
			return "", "", err
		}
		if !exists {
			return "", "", fmt.Errorf("character not found: %s", request.Character)
		}
		if state.OwnerID != formattedUserID || state.AttrsType != attributestate.AttrsTypeCharacter {
			return "", "", errors.New("character not owned by user or invalid type")
		}
		return request.Character, state.Name, nil
	}
	if request.NameSet && request.Name != "" {
		charID, err := svc.attrs().CharIdGetByNameForTransaction(ctx, tx, formattedUserID, request.Name)
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
