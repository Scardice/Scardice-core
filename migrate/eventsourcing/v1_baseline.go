package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

type v1ProjectionKey struct{ name, row string }

// Baselines deliberately reset aggregate and secret versions together. Only
// the published current state is authoritative; historical events and secret
// versions are not read by the converter.
type v1Baseline struct {
	records        []SourceRecord
	projections    map[v1ProjectionKey][]byte
	secretVersions map[string]uint64
	secretAliases  map[string]string
	moderation     []v1reader.ProjectionRow
}

func newV1Baseline() *v1Baseline {
	return &v1Baseline{projections: map[v1ProjectionKey][]byte{}, secretVersions: map[string]uint64{}, secretAliases: map[string]string{}}
}

func decodeV1Projection(payload []byte, state any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil {
		return fmt.Errorf("decode published v1 state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrValidation
	}
	return nil
}

func (b *v1Baseline) reference(ref string, version uint64) error {
	if ref == "" {
		return ErrValidation
	}
	if previous, exists := b.secretVersions[ref]; exists && previous != 0 && version != 0 && previous != version {
		return fmt.Errorf("current projections reference different versions of secret %q: %w", ref, ErrValidation)
	}
	if version != 0 || b.secretVersions[ref] == 0 {
		b.secretVersions[ref] = version
	}
	return nil
}

func (b *v1Baseline) expect(row v1reader.ProjectionRow, stream eventstore.StreamID, state any, records []SourceRecord) error {
	if stream.AggregateID == "" || stream.AggregateID != row.RowKey || len(records) == 0 {
		return ErrValidation
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	key := v1ProjectionKey{row.Name, row.RowKey}
	if _, duplicate := b.projections[key]; duplicate {
		return ErrValidation
	}
	b.projections[key] = payload
	b.records = append(b.records, records...)
	return nil
}

func (b *v1Baseline) addProjection(row v1reader.ProjectionRow) error {
	fail := func(err error) error { return fmt.Errorf("v1 current projection %s/%s: %w", row.Name, row.RowKey, err) }
	switch row.Name {
	case attributestate.ProjectionName:
		var state attributestate.State
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if err := attributestate.ValidateState(state); err != nil {
			return fail(err)
		}
		if err := b.reference(state.SecretRef, state.SecretVersion); err != nil {
			return fail(err)
		}
		b.secretAliases[state.SecretRef] = attributestate.SecretRef(state.DiceID, state.ID)
		state.SecretRef = b.secretAliases[state.SecretRef]
		state.Version, state.SecretVersion = 1, 1
		payload, err := attributestate.MarshalBaselineImportedV1(attributestate.NewBaselineImportedV1(state))
		if err != nil {
			return fail(err)
		}
		stream := attributestate.Stream(state.DiceID, state.ID)
		return b.expect(row, stream, state, []SourceRecord{legacyEventRecord(stream, attributestate.EventBaselineImported, attributestate.EventSchemaVersion, 1, payload)})
	case managerstate.ProjectionName:
		var state managerstate.State
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if err := managerstate.ValidateState(state); err != nil {
			return fail(err)
		}
		if err := b.reference(state.AuthSecretRef, state.AuthSecretVersion); err != nil {
			return fail(err)
		}
		state.Version, state.AuthSecretVersion = 1, 1
		payload, err := managerstate.MarshalSnapshotV1(managerstate.NewSnapshotV1(state.Public, 1))
		if err != nil {
			return fail(err)
		}
		stream := managerstate.Stream()
		return b.expect(row, stream, state, []SourceRecord{legacyEventRecord(stream, managerstate.EventBaselineImported, managerstate.EventSchemaVersion, 1, payload)})
	case configstate.ConfigProjectionName:
		var state configstate.State
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if state.Version == 0 {
			return fail(ErrValidation)
		}
		baseline := configstate.Baseline{DiceID: state.DiceID, ConfigVersion: state.ConfigVersion, Base: state.Base, Rate: state.Rate, Quit: state.Quit,
			Extension: state.Extension, Ban: state.Ban, JS: state.JS, StoryLog: state.StoryLog, Mail: state.Mail, News: state.News,
			PublicDice: state.PublicDice, Censor: state.Censor, Store: state.Store, Advanced: state.Advanced,
			CommandPrefix: state.Outer.CommandPrefix, DiceMasters: state.Outer.DiceMasters, UpgradeWindowID: state.Outer.UpgradeWindowID, UpgradeEndpointID: state.Outer.UpgradeEndpointID}
		decision, err := configstate.Decide(configstate.State{}, configstate.Command{Kind: configstate.CommandImportBaseline, Baseline: &baseline})
		if err != nil {
			return fail(err)
		}
		stream := configstate.ConfigStream(state.DiceID)
		records := make([]SourceRecord, 0, len(decision.Events))
		for i, event := range decision.Events {
			payload, err := configstate.MarshalTypedEvent(event)
			if err != nil {
				return fail(err)
			}
			records = append(records, legacyEventRecord(stream, string(event.EventType()), configstate.ConfigEventSchemaVersion, uint64(i+1), payload))
		}
		for _, ref := range []string{state.Mail.MailPasswordRef, state.Advanced.StoryLogBackendTokenRef} {
			if ref != "" {
				if err := b.reference(ref, 0); err != nil {
					return fail(err)
				}
			}
		}
		state.Version = uint64(len(records))
		return b.expect(row, stream, state, records)
	case groupstate.GroupProjectionName:
		var state groupstate.State
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if state.Version == 0 {
			return fail(ErrValidation)
		}
		if err := groupstate.ValidateState(state); err != nil {
			return fail(err)
		}
		events := []groupstate.TypedEvent{groupstate.NewGroupCreatedWithInviteV1(state.DiceID, state.GroupID, state.GroupName, state.InviteUserID, state.EnteredAt),
			groupstate.NewGroupIdentityChangedV1(state.GuildID, state.ChannelID), groupstate.NewGroupSystemChangedV1(state.System),
			groupstate.NewGroupTemplateWithCocRuleV1(state.DiceSideNum, state.DiceSideExpr, state.RollShaperMode, state.CocRuleIndex),
			groupstate.NewGroupHelpChangedV1(state.DefaultHelpGroup, state.HelpPackages), groupstate.NewGroupWelcomeChangedV1(state.ShowGroupWelcome, state.GroupWelcomeMessage)}
		for _, id := range unionLegacyKeys(state.DiceIDActive, state.DiceIDExists) {
			events = append(events, groupstate.NewGroupActivationChangedV1(id, state.DiceIDActive[id], state.DiceIDExists[id]))
		}
		for _, id := range state.ActivatedExtensions {
			events = append(events, groupstate.NewGroupExtensionChangedV1(id, true))
		}
		for _, id := range sortedLegacyBoolKeys(state.InactivatedExtensions) {
			if state.InactivatedExtensions[id] {
				events = append(events, groupstate.NewGroupExtensionChangedV1(id, false))
			}
		}
		for _, id := range sortedLegacyBoolKeys(state.BotList) {
			if state.BotList[id] {
				events = append(events, groupstate.NewGroupBotListChangedV1(id, true))
			}
		}
		for _, id := range sortedV1Keys(state.Privileges) {
			events = append(events, groupstate.NewGroupPrivilegeChangedV1(id, state.Privileges[id]))
		}
		for _, name := range sortedV1Keys(state.PlayerGroups) {
			events = append(events, groupstate.NewGroupTeamChangedV1(name, state.PlayerGroups[name], false))
		}
		if state.Deleted {
			events = append(events, groupstate.NewGroupRecordDeletedV1())
		}
		stream := groupstate.GroupStream(state.DiceID, state.GroupID)
		records := make([]SourceRecord, 0, len(events))
		for i, event := range events {
			payload, err := groupstate.MarshalTypedEvent(event)
			if err != nil {
				return fail(err)
			}
			records = append(records, legacyEventRecord(stream, string(event.EventType()), groupstate.GroupEventSchemaVersion, uint64(i+1), payload))
		}
		state.Version = uint64(len(records))
		return b.expect(row, stream, state, records)
	case playerstate.PlayerProjectionName:
		var state playerstate.PlayerState
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if state.Version == 0 {
			return fail(ErrValidation)
		}
		events := []playerstate.PlayerEvent{playerstate.NewPlayerCreatedV1(state.DiceID, state.GroupID, state.UserID, state.Name),
			playerstate.NewPlayerPrivilegeChangedV1(state.Privilege), playerstate.NewPlayerAutoSetNameTemplateChangedV1(state.AutoSetNameTemplate),
			playerstate.NewPlayerLastCommandChangedV1(state.LastCommandAt), playerstate.NewPlayerDiceSideChangedV1(state.DiceSideNum)}
		if state.Deleted {
			events = append(events, playerstate.NewPlayerDeletedV1())
		}
		stream := playerstate.PlayerStream(state.DiceID, state.GroupID, state.UserID)
		records := make([]SourceRecord, 0, len(events))
		for i, event := range events {
			payload, err := playerstate.MarshalPlayerEvent(event)
			if err != nil {
				return fail(err)
			}
			records = append(records, legacyEventRecord(stream, string(event.EventType()), playerstate.EventSchemaVersion, uint64(i+1), payload))
		}
		state.Version = uint64(len(records))
		return b.expect(row, stream, state, records)
	case playerstate.ModerationProjectionName:
		var state playerstate.ModerationState
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if state.Version == 0 {
			return fail(ErrValidation)
		}
		stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
		if stream.AggregateID == "" || stream.AggregateID != row.RowKey {
			return fail(ErrValidation)
		}
		if !state.Deleted || state.ReasonDigest != "" {
			old := sha256.Sum256([]byte(stream.AggregateID))
			ref := "vault:moderation-details:" + hex.EncodeToString(old[:16])
			b.secretAliases[ref] = "vault:moderation-details:" + stream.AggregateID
			if err := b.reference(ref, 0); err != nil {
				return fail(err)
			}
		}
		b.moderation = append(b.moderation, row)
		return nil
	case extensionstate.ExtensionProjectionName:
		return b.extension(row)
	case endpoint.EndpointProjectionName:
		var state endpoint.EndpointView
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return fail(err)
		}
		if state.Version == 0 {
			return fail(ErrValidation)
		}
		rewrites := make(map[adapterapi.SecretRef]adapterapi.SecretRef, len(state.Config.SecretRefs))
		for i := range state.Config.SecretRefs {
			original := state.Config.SecretRefs[i]
			if err := b.reference(original.Ref, original.Version); err != nil {
				return fail(err)
			}
			replacement := adapterapi.SecretRef{Ref: original.Ref, Version: 1}
			if alias, exists := b.secretAliases[original.Ref]; exists {
				replacement.Ref = alias
			}
			rewrites[original] = replacement
			state.Config.SecretRefs[i] = replacement
		}
		canonical, err := rebaseV1ConfigSecretRefs(state.Config.Canonical, rewrites)
		if err != nil {
			return fail(err)
		}
		state.Config.Canonical = canonical
		event, err := endpoint.NewBaselineImported(state, "v1-baseline-"+row.RowKey, "v1-baseline-"+row.RowKey)
		if err != nil {
			return fail(err)
		}
		payload, err := json.Marshal(event)
		if err != nil {
			return fail(err)
		}
		stream := eventstore.StreamID{AggregateType: endpoint.EndpointAggregateType, AggregateID: row.RowKey}
		record := legacyEventRecord(stream, string(event.Type), 1, 1, payload)
		record.EventID, record.CommandID, record.CorrelationID = event.EventID, event.CommandID, event.CorrelationID
		state.Version, state.DesiredVersion, state.Generation = 1, 1, 0
		state.ObservedState, state.OperationState = event.ObservedState, event.OperationState
		state.OperationID, state.CorrelationID = event.OperationID, event.CorrelationID
		return b.expect(row, stream, state, []SourceRecord{record})
	case endpoint.OperationProjectionName:
		// This read model is an operation ledger, excluded with operations/outbox.
		return nil
	case playerstate.GroupUserAttrsProjectionName, playerstate.CharacterProjectionName:
		return b.legacyAttributes(row)
	default:
		return fail(fmt.Errorf("unsupported current projection: %w", ErrValidation))
	}
}

func sortedV1Keys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (b *v1Baseline) extension(row v1reader.ProjectionRow) error {
	var state extensionstate.State
	if err := decodeV1Projection(row.Payload, &state); err != nil {
		return err
	}
	if state.Version == 0 {
		return ErrValidation
	}
	if err := extensionstate.ValidateState(state); err != nil {
		return err
	}
	baseline := extensionstate.Baseline{}
	for _, id := range state.ExtensionOrder {
		baseline.Extensions = append(baseline.Extensions, state.Extensions[id])
	}
	for _, id := range sortedV1Keys(state.EnabledExtensions) {
		if state.EnabledExtensions[id] {
			baseline.Enable = append(baseline.Enable, id)
		} else {
			baseline.Disable = append(baseline.Disable, id)
		}
	}
	for _, id := range sortedV1Keys(state.DefaultCommands) {
		config := state.DefaultCommands[id]
		baseline.Defaults = append(baseline.Defaults, extensionstate.DefaultCommandUpdate{ExtensionID: id, AutoActive: config.AutoActive, DisabledCommands: sortedLegacyBoolKeys(config.DisabledCommands)})
	}
	for _, id := range sortedV1Keys(state.ConfigDefinitions) {
		for _, key := range sortedV1Keys(state.ConfigDefinitions[id]) {
			baseline.Definitions = append(baseline.Definitions, state.ConfigDefinitions[id][key])
		}
	}
	for _, definition := range baseline.Definitions {
		if definition.DefaultSet && definition.Default.Type == extensionstate.ConfigSecret {
			if err := b.reference(definition.Default.SecretRef, 0); err != nil {
				return err
			}
		}
	}
	for _, id := range sortedV1Keys(state.ConfigValues) {
		for _, key := range sortedV1Keys(state.ConfigValues[id]) {
			value := state.ConfigValues[id][key]
			baseline.Values = append(baseline.Values, extensionstate.ConfigUpdate{ExtensionID: id, Key: key, Value: value})
			if value.Type == extensionstate.ConfigSecret {
				if err := b.reference(value.SecretRef, 0); err != nil {
					return err
				}
			}
		}
	}
	for _, id := range sortedV1Keys(state.DisabledScripts) {
		if state.DisabledScripts[id] {
			baseline.DisabledScripts = append(baseline.DisabledScripts, id)
		}
	}
	decision, err := extensionstate.Decide(extensionstate.State{}, extensionstate.Command{Kind: extensionstate.CommandImportBaseline, DiceID: state.DiceID, Baseline: &baseline})
	if err != nil {
		return err
	}
	stream := extensionstate.ExtensionStream(state.DiceID)
	records := make([]SourceRecord, 0, len(decision.Events))
	for i, event := range decision.Events {
		payload, err := extensionstate.MarshalEvent(event)
		if err != nil {
			return err
		}
		records = append(records, legacyEventRecord(stream, string(event.EventType()), extensionstate.ExtensionEventSchemaVersion, uint64(i+1), payload))
	}
	state.Version = uint64(len(records))
	return b.expect(row, stream, state, records)
}

// Legacy attribute read models contain opaque, unbound ciphertext in old
// installations. Never guess its crypto contract or reset a current value.
// An empty current owner can be mapped without consulting historical events.
func (b *v1Baseline) legacyAttributes(row v1reader.ProjectionRow) error {
	state := attributestate.State{Version: 1, SecretVersion: 1}
	if row.Name == playerstate.GroupUserAttrsProjectionName {
		var legacy playerstate.GroupUserAttrsState
		if err := decodeV1Projection(row.Payload, &legacy); err != nil {
			return err
		}
		if legacy.Version == 0 || len(legacy.Values) != 0 || !v1LegacyAttributesProvablyEmpty(legacy.Operations) {
			return fmt.Errorf("v1 current group-user attribute values lack the nonce/AAD contract: %w", ErrValidation)
		}
		if playerstate.GroupUserAttrsStream(legacy.DiceID, legacy.GroupID, legacy.UserID).AggregateID != row.RowKey {
			return ErrValidation
		}
		state.DiceID, state.ID, state.AttrsType, state.BindingSheetID = legacy.DiceID, legacy.GroupID+"-"+legacy.UserID, attributestate.AttrsTypeGroupUser, legacy.BindingSheetID
	} else {
		var legacy playerstate.CharacterState
		if err := decodeV1Projection(row.Payload, &legacy); err != nil {
			return err
		}
		if legacy.Version == 0 || (!legacy.Deleted && len(legacy.Sheet) != 0) {
			return fmt.Errorf("v1 current character sheet lacks the nonce/AAD contract: %w", ErrValidation)
		}
		if playerstate.CharacterStream(legacy.DiceID, legacy.UserID, legacy.CharacterID).AggregateID != row.RowKey {
			return ErrValidation
		}
		state.DiceID, state.ID, state.AttrsType = legacy.DiceID, legacy.CharacterID, attributestate.AttrsTypeCharacter
		state.Name, state.OwnerID, state.SheetType = legacy.Name, legacy.UserID, legacy.SheetType
		if legacy.Deleted {
			state.AttrsType, state.Name, state.OwnerID, state.SheetType = "", "", "", ""
		}
	}
	state.SecretRef = attributestate.SecretRef(state.DiceID, state.ID)
	stream := attributestate.Stream(state.DiceID, state.ID)
	if _, exists := b.projections[v1ProjectionKey{attributestate.ProjectionName, stream.AggregateID}]; exists {
		return fmt.Errorf("duplicate v1 current attribute owner %q: %w", state.ID, ErrValidation)
	}
	payload, err := attributestate.MarshalBaselineImportedV1(attributestate.NewBaselineImportedV1(state))
	if err != nil {
		return err
	}
	if err = b.expect(v1reader.ProjectionRow{Name: attributestate.ProjectionName, RowKey: stream.AggregateID}, stream, state,
		[]SourceRecord{legacyEventRecord(stream, attributestate.EventBaselineImported, 1, 1, payload)}); err != nil {
		return err
	}
	b.records = append(b.records, sensitiveLegacyRecord(attributestate.AggregateType, state.SecretRef, state.ID, []byte(`{"t":7,"v":{"dict":{}}}`)))
	return nil
}

func (b *v1Baseline) addSecrets(ctx context.Context, source *v1reader.Source) error {
	secrets, err := source.ReferencedSecrets(ctx, sortedV1Keys(b.secretVersions))
	if err != nil {
		return err
	}
	defer func() {
		for i := range secrets {
			clear(secrets[i].Plaintext)
		}
	}()
	seen := make(map[string]v1reader.Secret, len(secrets))
	for _, secret := range secrets {
		if version, required := b.secretVersions[secret.Ref]; required && version != 0 && version != secret.Version {
			return fmt.Errorf("current projection references nonlatest secret %q: %w", secret.Ref, ErrValidation)
		}
		seen[secret.Ref] = secret
		ref := secret.Ref
		if mapped, exists := b.secretAliases[ref]; exists {
			ref = mapped
		}
		b.records = append(b.records, sensitiveLegacyRecord(secret.AdapterID, ref, secret.EndpointID, bytes.Clone(secret.Plaintext)))
	}
	for ref := range b.secretVersions {
		if _, exists := seen[ref]; !exists {
			return fmt.Errorf("current projection secret %q is missing: %w", ref, ErrValidation)
		}
	}
	return b.finishModeration(seen)
}

// The v1 sensitive-config route stored the effective current typed value
// (including the initial default) in a reserved plugin KV slot. Fold only
// slots proved by published plugin names and definitions, never a broad prefix
// deletion of ordinary plugin storage.
func foldV1PluginConfig(rows []v1reader.ProjectionRow, items []v1reader.PluginKV) ([]v1reader.ProjectionRow, []v1reader.PluginKV, error) {
	const prefix = "scardice.internal.config/v1/"
	type owner struct {
		row       int
		extension string
	}
	states := make(map[int]*extensionstate.State)
	owners := make(map[string][]owner)
	for i, row := range rows {
		if row.Name != extensionstate.ExtensionProjectionName {
			continue
		}
		var state extensionstate.State
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return nil, nil, err
		}
		states[i] = &state
		for extension := range state.ConfigDefinitions {
			digest := sha256.Sum256([]byte(extension))
			namespace := prefix + hex.EncodeToString(digest[:])
			owners[namespace] = append(owners[namespace], owner{i, extension})
		}
	}
	remaining := make([]v1reader.PluginKV, 0, len(items))
	for _, item := range items {
		matches := owners[item.ExtensionID]
		if len(matches) == 0 {
			if strings.HasPrefix(item.ExtensionID, prefix) {
				suffix := strings.TrimPrefix(item.ExtensionID, prefix)
				if digest, err := hex.DecodeString(suffix); err == nil && len(digest) == sha256.Size {
					return nil, nil, fmt.Errorf("v1 internal config has no published owner: %w", ErrValidation)
				}
			}
			remaining = append(remaining, item)
			continue
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(item.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("v1 internal config key: %w", ErrValidation)
		}
		key := string(keyBytes)
		var value extensionstate.ConfigValue
		if err = decodeV1Projection(item.Value, &value); err != nil {
			return nil, nil, err
		}
		for _, match := range matches {
			state := states[match.row]
			definition, exists := state.ConfigDefinitions[match.extension][key]
			if !exists || definition.Type != value.Type {
				return nil, nil, fmt.Errorf("v1 internal config lacks a matching typed definition: %w", ErrValidation)
			}
			if state.ConfigValues == nil {
				state.ConfigValues = map[string]map[string]extensionstate.ConfigValue{}
			}
			if state.ConfigValues[match.extension] == nil {
				state.ConfigValues[match.extension] = map[string]extensionstate.ConfigValue{}
			}
			state.ConfigValues[match.extension][key] = value
		}
	}
	for i, state := range states {
		payload, err := json.Marshal(state)
		if err != nil {
			return nil, nil, err
		}
		rows[i].Payload = payload
	}
	return rows, remaining, nil
}

func v1LegacyAttributesProvablyEmpty(operations []playerstate.AttributeOperation) bool {
	unknown := map[string]bool{}
	for _, operation := range operations {
		switch operation.Kind {
		case playerstate.OperationSet, playerstate.OperationIncrement:
			unknown[operation.Key] = true
		case playerstate.OperationDelete:
			delete(unknown, operation.Key)
		case playerstate.OperationClear:
			clear(unknown)
		default:
			return false
		}
	}
	return len(unknown) == 0
}

func (b *v1Baseline) finishModeration(secrets map[string]v1reader.Secret) error {
	for _, row := range b.moderation {
		var state playerstate.ModerationState
		if err := decodeV1Projection(row.Payload, &state); err != nil {
			return err
		}
		stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
		if !state.Deleted || state.ReasonDigest != "" {
			old := sha256.Sum256([]byte(stream.AggregateID))
			secret, exists := secrets["vault:moderation-details:"+hex.EncodeToString(old[:16])]
			if !exists {
				return fmt.Errorf("current moderation history is missing: %w", ErrValidation)
			}
			// This is the runtime's exact typed history JSON contract, not the
			// surrounding details document or the previous v1 keyed digest.
			var history struct {
				Times   []int64  `json:"times"`
				Reasons []string `json:"reasons"`
				Places  []string `json:"places"`
			}
			if err := json.Unmarshal(secret.Plaintext, &history); err != nil {
				return err
			}
			payload, err := json.Marshal(history)
			if err != nil {
				return err
			}
			state.ReasonDigest = hex.EncodeToString(eventstore.DigestBytes("moderation-history/v1", payload))
		}
		events := []playerstate.ModerationEvent{playerstate.NewModerationCreatedV1(state.DiceID, state.GroupID, state.SubjectID, state.Rank, state.Score)}
		if state.ReasonDigest != "" {
			events = append(events, playerstate.NewModerationScoreChangedV1(state.Score, state.ReasonDigest))
		}
		if state.Deleted {
			events = append(events, playerstate.NewModerationDeletedV1())
		}
		records := make([]SourceRecord, 0, len(events))
		for i, event := range events {
			payload, err := playerstate.MarshalModerationEvent(event)
			if err != nil {
				return err
			}
			records = append(records, legacyEventRecord(stream, string(event.EventType()), playerstate.EventSchemaVersion, uint64(i+1), payload))
		}
		state.Version = uint64(len(records))
		if err := b.expect(row, stream, state, records); err != nil {
			return err
		}
	}
	b.moderation = nil
	return nil
}

// Descriptor configs use either adapterapi.SecretRef {ref,version} or the
// provider canonical shape {secretRef,version}. Rewrite only current refs
// declared by ValidatedConfig, leaving unrelated version fields and numbers
// byte-semantically intact.
func rebaseV1ConfigSecretRefs(raw json.RawMessage, rewrites map[adapterapi.SecretRef]adapterapi.SecretRef) (json.RawMessage, error) {
	if len(rewrites) == 0 {
		return raw, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrValidation
	}
	known := make(map[string]bool, len(rewrites))
	for ref := range rewrites {
		known[ref.Ref] = true
	}
	var visit func(any) error
	visit = func(value any) error {
		switch object := value.(type) {
		case map[string]any:
			for _, field := range []string{"ref", "secretRef"} {
				ref, isString := object[field].(string)
				if !isString || !known[ref] {
					continue
				}
				number, ok := object["version"].(json.Number)
				if !ok {
					return fmt.Errorf("current endpoint secret reference lacks a version: %w", ErrValidation)
				}
				version, err := strconv.ParseUint(number.String(), 10, 64)
				if err != nil {
					return ErrValidation
				}
				replacement, exists := rewrites[adapterapi.SecretRef{Ref: ref, Version: version}]
				if !exists {
					return fmt.Errorf("endpoint canonical config disagrees with declared secret version: %w", ErrValidation)
				}
				object[field], object["version"] = replacement.Ref, json.Number(strconv.FormatUint(replacement.Version, 10))
			}
			for _, child := range object {
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range object {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return adapterapi.CanonicalizeJSON(encoded)
}
