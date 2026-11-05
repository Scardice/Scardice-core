package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	sealdicelogger "Scardice-core/logger"

	"gorm.io/gorm"
)

var ErrPrivacyConfirmationMismatch = errors.New("eventstore: privacy confirmation is stale or invalid")
var _ GroupPrivacyRepository = (*GORMStore)(nil)

const privacyReadPageSize = 500

func privacyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"group_record"}, nil
	}
	seen := make(map[string]bool)
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		switch scope {
		case "group_record", "players", "attrs", "logs":
			seen[scope] = true
		default:
			return nil, ErrInvalidMetadata
		}
	}
	out := make([]string, 0, len(seen))
	for _, scope := range []string{"group_record", "players", "attrs", "logs"} {
		if seen[scope] {
			out = append(out, scope)
		}
	}
	return out, nil
}
func privacyHasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}
func privacyCanonical(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return b.String()
}
func privacyLikePrefix(value string) string {
	return strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value) + `%`
}
func privacyDecodeParts(value string, want int) ([]string, bool) {
	out := make([]string, 0, want)
	for len(value) > 0 && len(out) < want {
		idx := strings.IndexByte(value, ':')
		if idx <= 0 {
			return nil, false
		}
		n, err := strconv.Atoi(value[:idx])
		if err != nil || n < 0 || len(value)-idx-1 < n {
			return nil, false
		}
		out = append(out, value[idx+1:idx+1+n])
		value = value[idx+1+n:]
	}
	return out, len(out) == want && value == ""
}

type privacyGroupUserPrefix struct{ group, user string }

var privacyGroupUserPrefixes = [...]privacyGroupUserPrefix{
	{"QQ-Group:", "QQ:"}, {"QQ-CH-Group:", "QQ-CH:"}, {"KOOK-CH-Group:", "KOOK:"}, {"DODO-Group:", "DODO:"}, {"TG-Group:", "TG:"}, {"DISCORD-CH-Group:", "DISCORD:"}, {"SEALCHAT-Group:", "SEALCHAT:"}, {"SLACK-CH-Group", "SLACK:"}, {"DINGTALK-Group", "DINGTALK:"}, {"OpenQQCH-Channel:", "OpenQQCH:"}, {"OpenQQ-Group-T:", "OpenQQ-Member-T:"}, {"UI-Group:", "UI:"},
	{"PG-QQ:", "QQ:"}, {"PG-KOOK:", "KOOK:"}, {"PG-SEALCHAT:", "SEALCHAT:"}, {"PG-UI:", "UI:"}, {"PG-DISCORD:", "DISCORD:"}, {"PG-DODO:", "DODO:"}, {"PG-SLACK:", "SLACK:"}, {"PG-TG:", "TG:"}, {"PG-DINGTALK:", "DINGTALK:"}, {"PG-OpenQQCH:", "OpenQQCH:"},
}

func privacyGroupUserOwner(id string) (string, bool) {
	for _, prefix := range privacyGroupUserPrefixes {
		if !strings.HasPrefix(id, prefix.group) {
			continue
		}
		idx := strings.Index(id[len(prefix.group):], "-"+prefix.user)
		if idx >= 0 {
			return id[:len(prefix.group)+idx], true
		}
	}
	return "", false
}
func privacyGroupAttributeIdentity(id, attrsType string) (groupID string, groupLike, scoped bool) {
	if group, ok := privacyGroupUserOwner(id); ok {
		return group, true, true
	}
	if attrsType == "group_user" {
		return "", true, false
	}
	for _, prefix := range privacyGroupUserPrefixes {
		if strings.HasPrefix(id, prefix.group) {
			return id, true, true
		}
	}
	if attrsType == "group" {
		return id, true, true
	}
	return "", false, false
}

type privacyAttribute struct {
	DiceID         string `json:"diceId"`
	ID             string `json:"id"`
	AttrsType      string `json:"attrsType"`
	SecretRef      string `json:"secretRef"`
	OwnerID        string `json:"ownerId"`
	BindingSheetID string `json:"bindingSheetId"`
}

func privacyAttributeSnapshot(id string, payload []byte) (privacyAttribute, bool) {
	parts, ok := privacyDecodeParts(id, 2)
	if !ok {
		return privacyAttribute{}, false
	}
	var snapshot privacyAttribute
	if json.Unmarshal(payload, &snapshot) != nil || snapshot.DiceID != parts[0] || snapshot.ID != parts[1] {
		return privacyAttribute{}, false
	}
	return snapshot, true
}
func privacyRecordSelection(row domainEventRow, req PrivacyDryRunRequest) (selected, ambiguous bool) {
	if row.AggregateType != "attributes" {
		for _, dice := range req.DiceIDs {
			prefix := privacyCanonical(dice, req.GroupID)
			switch row.AggregateType {
			case "group", "attrs/group":
				if row.AggregateID == prefix {
					return true, false
				}
			case "player", "attrs/group-user":
				if strings.HasPrefix(row.AggregateID, prefix) {
					return true, false
				}
			}
		}
		return false, false
	}
	snapshot, ok := privacyAttributeSnapshot(row.AggregateID, row.Payload)
	if !ok {
		return false, false
	}
	wantedDice := false
	for _, dice := range req.DiceIDs {
		if snapshot.DiceID == dice {
			wantedDice = true
			break
		}
	}
	if !wantedDice {
		return false, false
	}
	group, like, scoped := privacyGroupAttributeIdentity(snapshot.ID, snapshot.AttrsType)
	if like && scoped {
		return group == req.GroupID, false
	}
	return false, snapshot.AttrsType == "group_user" && (snapshot.ID == req.GroupID || strings.HasPrefix(snapshot.ID, req.GroupID+"-"))
}
func canonicalPrivacyRequest(req PrivacyDryRunRequest) (PrivacyDryRunRequest, error) {
	if strings.TrimSpace(req.GroupID) == "" || len(req.DiceIDs) == 0 {
		return req, ErrInvalidMetadata
	}
	scopes, err := privacyScopes(req.Scopes)
	if err != nil {
		return req, err
	}
	req.Scopes = scopes
	dice := append([]string(nil), req.DiceIDs...)
	sort.Strings(dice)
	req.DiceIDs = make([]string, 0, len(dice))
	for _, id := range dice {
		if strings.TrimSpace(id) == "" {
			return req, ErrInvalidMetadata
		}
		if len(req.DiceIDs) == 0 || req.DiceIDs[len(req.DiceIDs)-1] != id {
			req.DiceIDs = append(req.DiceIDs, id)
		}
	}
	req.ActiveDiceIDs = append([]string(nil), req.ActiveDiceIDs...)
	sort.Strings(req.ActiveDiceIDs)
	return req, nil
}
func privacyConditions(req PrivacyDryRunRequest) (string, []any) {
	clauses := make([]string, 0)
	args := make([]any, 0)
	for _, dice := range req.DiceIDs {
		for _, scope := range req.Scopes {
			switch scope {
			case "group_record":
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id = ?)")
				args = append(args, "group", privacyCanonical(dice, req.GroupID))
			case "players":
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id LIKE ? ESCAPE '!')")
				args = append(args, "player", privacyLikePrefix(privacyCanonical(dice, req.GroupID)))
			case "attrs":
				clauses = append(clauses, "(aggregate_type IN ? AND (aggregate_id = ? OR aggregate_id LIKE ? ESCAPE '!'))")
				args = append(args, []string{"attrs/group", "attrs/group-user"}, privacyCanonical(dice, req.GroupID), privacyLikePrefix(privacyCanonical(dice, req.GroupID)))
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id LIKE ? ESCAPE '!')")
				args = append(args, "attributes", privacyLikePrefix(privacyCanonical(dice)))
			}
		}
	}
	if len(clauses) == 0 {
		return "1 = 0", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}

type privacySecretIdentity struct{ ref, endpoint, adapter string }
type privacyProjectionIdentity struct{ generation, name, key string }
type privacySelection struct {
	streams     []StreamID
	secrets     []privacySecretIdentity
	projections []privacyProjectionIdentity
	catalogs    map[revisionResourceKey]struct{}
	queueLanes  []queueLaneRef
	result      PrivacyDryRunResult
}

// Hash raw fields directly: JSON would normalize opaque strings and copy/encode
// every retained payload before hashing it.
func writePrivacyRecord(h hash.Hash, table string, row any) error {
	writeCanonicalString(h, table)
	return writePrivacyValue(h, reflect.ValueOf(row))
}
func writePrivacyValue(h hash.Hash, value reflect.Value) error {
	if !value.IsValid() {
		writeCanonicalBytes(h, nil, true)
		return nil
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			writeCanonicalBytes(h, nil, true)
			return nil
		}
		return writePrivacyValue(h, value.Elem())
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		at := value.Interface().(time.Time)
		writeCanonicalInt64(h, at.Unix())
		writeCanonicalUint64(h, uint64(at.Nanosecond()))
		return nil
	}
	switch value.Kind() {
	case reflect.String:
		writeCanonicalString(h, value.String())
	case reflect.Bool:
		var flag uint64
		if value.Bool() {
			flag = 1
		}
		writeCanonicalUint64(h, flag)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		writeCanonicalInt64(h, value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		writeCanonicalUint64(h, value.Uint())
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			writeCanonicalBytes(h, value.Bytes(), value.IsNil())
			return nil
		}
		writeCanonicalUint64(h, uint64(value.Len()))
		for i := range value.Len() {
			if err := writePrivacyValue(h, value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Array:
		writeCanonicalUint64(h, uint64(value.Len()))
		for i := range value.Len() {
			if err := writePrivacyValue(h, value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		writeCanonicalUint64(h, uint64(value.NumField()))
		for i := range value.NumField() {
			if err := writePrivacyValue(h, value.Field(i)); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidMetadata
	}
	return nil
}
func addPrivacyEventCount(counts *PrivacyCounts, typ string, n int64) {
	switch typ {
	case "group":
		counts.GroupRecord += n
	case "player":
		counts.Players += n
	case "attrs/group", "attrs/group-user", "attributes":
		counts.Attrs += n
	}
}
func privacyProjectionName(aggregate string) string {
	switch aggregate {
	case "group":
		return "group-record"
	case "player":
		return "player"
	case "attrs/group-user":
		return "group-user-attrs"
	case "attrs/group", "attributes":
		return "attributes"
	}
	return ""
}

func (s *GORMStore) selectPrivacyGroup(ctx context.Context, tx *gorm.DB, req PrivacyDryRunRequest) (privacySelection, error) {
	selection := privacySelection{catalogs: make(map[revisionResourceKey]struct{})}
	control, err := readPublishedProjectionControl(tx)
	if err != nil {
		return selection, err
	}
	h := sha256.New()
	if err := writePrivacyRecord(h, "selection", req); err != nil {
		return selection, err
	}
	streams := make(map[StreamID]struct{})
	secrets := make(map[privacySecretIdentity]struct{})
	condition, args := privacyConditions(req)
	var cursor uint64
	for {
		var page []domainEventRow
		if err := tx.WithContext(ctx).Where(condition+" AND global_position > ?", append(append([]any(nil), args...), cursor)...).Order("global_position ASC").Limit(privacyReadPageSize).Find(&page).Error; err != nil {
			return selection, ErrParticipantFailure
		}
		for _, row := range page {
			selected, ambiguous := privacyRecordSelection(row, req)
			if ambiguous {
				return selection, ErrInvalidMetadata
			}
			if !selected {
				continue
			}
			streams[StreamID{AggregateType: row.AggregateType, AggregateID: row.AggregateID}] = struct{}{}
		}
		if len(page) < privacyReadPageSize {
			break
		}
		cursor = page[len(page)-1].GlobalPosition
	}
	// Heads without history still belong to the selected stream and must disappear.
	var heads []aggregateHeadRow
	if err := tx.Where(condition, args...).Find(&heads).Error; err != nil {
		return selection, ErrParticipantFailure
	}
	for _, head := range heads {
		if head.AggregateType == "attributes" {
			parts, ok := privacyDecodeParts(head.AggregateID, 2)
			if !ok {
				continue
			}
			wantedDice := false
			for _, dice := range req.DiceIDs {
				if parts[0] == dice {
					wantedDice = true
					break
				}
			}
			if !wantedDice {
				continue
			}
			group, groupUser := privacyGroupUserOwner(parts[1])
			if parts[1] == req.GroupID || groupUser && group == req.GroupID {
				streams[StreamID{AggregateType: head.AggregateType, AggregateID: head.AggregateID}] = struct{}{}
			}
			continue
		}
		selected, _ := privacyRecordSelection(domainEventRow{AggregateType: head.AggregateType, AggregateID: head.AggregateID}, req)
		if selected {
			streams[StreamID{AggregateType: head.AggregateType, AggregateID: head.AggregateID}] = struct{}{}
		}
	}
	// Select covered projection namespaces explicitly, including surviving rows
	// whose aggregate head/history is already empty.
	for _, dice := range req.DiceIDs {
		candidates := []struct{ scope, aggregate, name, prefix string }{
			{"group_record", "group", "group-record", privacyCanonical(dice, req.GroupID)},
			{"players", "player", "player", privacyCanonical(dice, req.GroupID)},
			{"attrs", "attrs/group-user", "group-user-attrs", privacyCanonical(dice, req.GroupID)},
			{"attrs", "attributes", "attributes", privacyCanonical(dice)},
		}
		for _, candidate := range candidates {
			if !privacyHasScope(req.Scopes, candidate.scope) {
				continue
			}
			var rows []projectionReadModelRow
			if err := tx.Where("projection_name = ? AND row_key LIKE ? ESCAPE '!'", candidate.name, privacyLikePrefix(candidate.prefix)).Find(&rows).Error; err != nil {
				return selection, ErrParticipantFailure
			}
			for _, row := range rows {
				selected, ambiguous := privacyRecordSelection(domainEventRow{AggregateType: candidate.aggregate, AggregateID: row.RowKey, Payload: row.Payload}, req)
				if ambiguous {
					return selection, ErrInvalidMetadata
				}
				if selected {
					streams[StreamID{AggregateType: candidate.aggregate, AggregateID: row.RowKey}] = struct{}{}
				}
			}
		}
	}
	selection.streams = make([]StreamID, 0, len(streams))
	for stream := range streams {
		selection.streams = append(selection.streams, stream)
	}
	sort.Slice(selection.streams, func(i, j int) bool { return streamLess(selection.streams[i], selection.streams[j]) })
	captureAttribute := func(id string, payload []byte) {
		snapshot, ok := privacyAttributeSnapshot(id, payload)
		if !ok {
			return
		}
		if snapshot.SecretRef != "" {
			secrets[privacySecretIdentity{snapshot.SecretRef, snapshot.ID, "attributes"}] = struct{}{}
		}
		if snapshot.OwnerID != "" && snapshot.AttrsType == "character" {
			selection.catalogs[catalogResource("attributes/characters-by-owner/v1", privacyCanonical(snapshot.DiceID, snapshot.OwnerID))] = struct{}{}
		}
		if snapshot.BindingSheetID != "" {
			selection.catalogs[catalogResource("attributes/bindings-by-character/v1", privacyCanonical(snapshot.DiceID, snapshot.BindingSheetID))] = struct{}{}
		}
	}
	seenProjections := make(map[privacyProjectionIdentity]struct{})
	for _, stream := range selection.streams {
		var head aggregateHeadRow
		err := tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).Take(&head).Error
		if err == nil {
			if err := writePrivacyRecord(h, tableAggregateHeads, head); err != nil {
				return selection, err
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return selection, ErrParticipantFailure
		}
		var version uint64
		for {
			var rows []domainEventRow
			if err := tx.Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version > ?", stream.AggregateType, stream.AggregateID, version).Order("aggregate_version ASC").Limit(privacyReadPageSize).Find(&rows).Error; err != nil {
				return selection, ErrParticipantFailure
			}
			for _, row := range rows {
				if _, err := projectionEnvelope(row); err != nil {
					return selection, err
				}
				if err := writePrivacyRecord(h, tableDomainEvents, row); err != nil {
					return selection, err
				}
				addPrivacyEventCount(&selection.result.Counts, row.AggregateType, 1)
				if row.GlobalPosition > selection.result.Version {
					selection.result.Version = row.GlobalPosition
				}
				if stream.AggregateType == "attributes" {
					captureAttribute(row.AggregateID, row.Payload)
				}
			}
			if len(rows) < privacyReadPageSize {
				break
			}
			version = rows[len(rows)-1].AggregateVersion
		}
		name := privacyProjectionName(stream.AggregateType)
		var projections []projectionReadModelRow
		if name != "" {
			if err := textStringQuery(tx.Where("projection_name = ?", name), "row_key", stream.AggregateID).Order("projection_generation ASC").Find(&projections).Error; err != nil {
				return selection, ErrParticipantFailure
			}
		}
		for _, row := range projections {
			key := privacyProjectionIdentity{row.ProjectionGeneration, row.ProjectionName, row.RowKey}
			if _, seen := seenProjections[key]; seen {
				continue
			}
			seenProjections[key] = struct{}{}
			selection.projections = append(selection.projections, key)
			if err := writePrivacyRecord(h, tableProjectionReadModel, row); err != nil {
				return selection, err
			}
			selection.result.Counts.Projections++
			if row.ProjectionName == "attributes" {
				captureAttribute(row.RowKey, row.Payload)
			}
		}
	}
	selection.secrets = make([]privacySecretIdentity, 0, len(secrets))
	for key := range secrets {
		selection.secrets = append(selection.secrets, key)
	}
	sort.Slice(selection.secrets, func(i, j int) bool {
		a, b := selection.secrets[i], selection.secrets[j]
		if a.ref != b.ref {
			return a.ref < b.ref
		}
		if a.endpoint != b.endpoint {
			return a.endpoint < b.endpoint
		}
		return a.adapter < b.adapter
	})
	for _, key := range selection.secrets {
		var rows []adapterSecretRow
		if err := secretOwnerQuery(tx, key.ref, key.endpoint, key.adapter).Order("secret_version ASC").Find(&rows).Error; err != nil {
			return selection, ErrParticipantFailure
		}
		for _, row := range rows {
			if err := writePrivacyRecord(h, tableAdapterSecrets, row); err != nil {
				return selection, err
			}
			selection.result.Counts.Secrets++
		}
	}
	if privacyHasScope(req.Scopes, "logs") {
		if err := s.privacyStoryLogSelection(ctx, tx, req, h, &selection); err != nil {
			return selection, err
		}
	}
	if err := privacyQueueSelection(tx, req.GroupID, h, &selection); err != nil {
		return selection, err
	}
	active := make(map[string]bool)
	existing := make(map[string]bool)
	for _, dice := range req.ActiveDiceIDs {
		if dice != "" {
			active[dice] = true
		}
	}
	for _, dice := range req.DiceIDs {
		var row projectionReadModelRow
		err := textStringQuery(tx.Where("projection_generation = ? AND projection_name = ?", control.ActiveGeneration, "group-record"), "row_key", privacyCanonical(dice, req.GroupID)).Take(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return selection, ErrParticipantFailure
		}
		var state struct {
			DiceID       string          `json:"diceId"`
			GroupID      string          `json:"groupId"`
			Active       bool            `json:"active"`
			DiceIDActive map[string]bool `json:"diceIdActive"`
			DiceIDExists map[string]bool `json:"diceIdExists"`
		}
		if json.Unmarshal(row.Payload, &state) != nil || state.DiceID != dice || state.GroupID != req.GroupID {
			return selection, ErrInvalidMetadata
		}
		if state.Active {
			active[dice] = true
		}
		for id, on := range state.DiceIDActive {
			if on {
				active[id] = true
			}
		}
		for id, on := range state.DiceIDExists {
			if on {
				existing[id] = true
			}
		}
		if err := writePrivacyRecord(h, "group-activity", row.Payload); err != nil {
			return selection, err
		}
	}
	selection.result.ActiveDiceIDs = make([]string, 0, len(active))
	for id := range active {
		selection.result.ActiveDiceIDs = append(selection.result.ActiveDiceIDs, id)
	}
	sort.Strings(selection.result.ActiveDiceIDs)
	selection.result.ExistingDiceIDs = make([]string, 0, len(existing))
	for id := range existing {
		selection.result.ExistingDiceIDs = append(selection.result.ExistingDiceIDs, id)
	}
	sort.Strings(selection.result.ExistingDiceIDs)
	selection.result.Digest = h.Sum(nil)
	selection.result.Uncovered = []string{"moderation", "plugin KV", "user-global characters", "external stores", "backups"}
	for _, scope := range []string{"group_record", "players", "attrs", "logs"} {
		if !privacyHasScope(req.Scopes, scope) {
			selection.result.Uncovered = append(selection.result.Uncovered, scope)
		}
	}
	return selection, nil
}
func privacyQueueSelection(tx *gorm.DB, groupID string, h hash.Hash, selection *privacySelection) error {
	cursor := ""
	for {
		var rows []inboxMessageRow
		query := rawStringQuery(tx, "subject", groupID).Order("inbox_id ASC").Limit(privacyReadPageSize)
		if cursor != "" {
			query = query.Where("inbox_id > ?", cursor)
		}
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		for _, row := range rows {
			if err := writePrivacyRecord(h, tableInboxMessages, row); err != nil {
				return err
			}
			selection.result.Counts.Inbox++
			selection.queueLanes = append(selection.queueLanes, queueLaneRef{kind: inboxLaneKind, lane: row.Lane})
		}
		if len(rows) < privacyReadPageSize {
			break
		}
		cursor = rows[len(rows)-1].InboxID
	}
	cursor = ""
	for {
		var rows []outboxEffectRow
		query := rawStringQuery(tx, "subject", groupID).Order("effect_id ASC").Limit(privacyReadPageSize)
		if cursor != "" {
			query = query.Where("effect_id > ?", cursor)
		}
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		for _, row := range rows {
			if err := writePrivacyRecord(h, tableOutboxEffects, row); err != nil {
				return err
			}
			selection.result.Counts.Outbox++
			selection.queueLanes = append(selection.queueLanes, queueLaneRef{kind: outboxLaneKind, lane: row.Lane})
		}
		if len(rows) < privacyReadPageSize {
			break
		}
		cursor = rows[len(rows)-1].EffectID
	}
	return nil
}
func (s *GORMStore) PrivacyDryRun(ctx context.Context, req PrivacyDryRunRequest) (PrivacyDryRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return PrivacyDryRunResult{}, err
	}
	canonical, err := canonicalPrivacyRequest(req)
	if err != nil {
		return PrivacyDryRunResult{}, err
	}
	var selection privacySelection
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		var err error
		selection, err = s.selectPrivacyGroup(ctx, tx, canonical)
		return err
	})
	return selection.result, err
}
func (s *GORMStore) PrivacyDeleteGroup(ctx context.Context, req PrivacyDeleteRequest) (PrivacyDeleteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return PrivacyDeleteResult{}, err
	}
	canonical, err := canonicalPrivacyRequest(req.PrivacyDryRunRequest)
	if err != nil {
		return PrivacyDeleteResult{}, err
	}
	var result PrivacyDeleteResult
	err = s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.lockMutationPublication(ctx, tx); err != nil {
			return err
		}
		selection, err := s.selectPrivacyGroup(ctx, tx, canonical)
		if err != nil {
			return err
		}
		result.Scan = selection.result
		if req.ConfirmationVersion != selection.result.Version || !bytes.Equal(req.ConfirmationDigest, selection.result.Digest) {
			return ErrPrivacyConfirmationMismatch
		}
		if !req.AllowActive && len(selection.result.ActiveDiceIDs) != 0 {
			return ErrInvalidTransition
		}
		for _, stream := range selection.streams {
			q := tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).Delete(&domainEventRow{})
			if q.Error != nil {
				return ErrParticipantFailure
			}
			addPrivacyEventCount(&result.Deleted, stream.AggregateType, q.RowsAffected)
			if err := tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).Delete(&aggregateHeadRow{}).Error; err != nil {
				return ErrParticipantFailure
			}
		}
		for _, key := range selection.projections {
			q := textStringQuery(tx.Where("projection_generation = ? AND projection_name = ?", key.generation, key.name), "row_key", key.key).Delete(&projectionReadModelRow{})
			if q.Error != nil {
				return ErrParticipantFailure
			}
			result.Deleted.Projections += q.RowsAffected
		}
		for _, key := range selection.secrets {
			q := secretOwnerQuery(tx, key.ref, key.endpoint, key.adapter).Delete(&adapterSecretRow{})
			if q.Error != nil {
				return ErrParticipantFailure
			}
			result.Deleted.Secrets += q.RowsAffected
		}
		if privacyHasScope(canonical.Scopes, "logs") {
			if err := privacyDeleteStoryLogs(tx, canonical, &result.Deleted); err != nil {
				return err
			}
		}
		q := rawStringQuery(tx, "subject", canonical.GroupID).Delete(&inboxMessageRow{})
		if q.Error != nil {
			return ErrParticipantFailure
		}
		result.Deleted.Inbox = q.RowsAffected
		q = rawStringQuery(tx, "subject", canonical.GroupID).Delete(&outboxEffectRow{})
		if q.Error != nil {
			return ErrParticipantFailure
		}
		result.Deleted.Outbox = q.RowsAffected
		if err := refreshQueueLaneRefs(tx, selection.queueLanes, s.task5Now()); err != nil {
			return err
		}
		for resource := range selection.catalogs {
			if err := s.advancePrivacyCatalog(tx, resource); err != nil {
				return err
			}
		}
		var control projectionControlRow
		if err := tx.Where("singleton_id = ?", "default").Take(&control).Error; err != nil {
			return ErrParticipantFailure
		}
		generation, err := s.task5ID()
		if err != nil {
			return err
		}
		if generation == control.ActiveGeneration {
			return ErrParticipantConflict
		}
		if err := tx.Exec("INSERT INTO projection_read_models (projection_generation, projection_name, row_key, payload, updated_at) SELECT ?, projection_name, row_key, payload, updated_at FROM projection_read_models WHERE projection_generation = ?", generation, control.ActiveGeneration).Error; err != nil {
			return ErrParticipantFailure
		}
		if err := tx.Where("projection_generation <> ?", generation).Delete(&projectionReadModelRow{}).Error; err != nil {
			return ErrParticipantFailure
		}
		q = tx.Model(&projectionControlRow{}).Where("singleton_id = ? AND active_generation = ?", "default", control.ActiveGeneration).Updates(map[string]any{"active_generation": generation, "updated_at": s.task5Now()})
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if q.RowsAffected != 1 {
			return ErrParticipantConflict
		}
		if result.Deleted != selection.result.Counts {
			return ErrParticipantConflict
		}
		return nil
	})
	if err != nil {
		result.Deleted = PrivacyCounts{}
		return result, err
	}
	s.signalInboxWork()
	s.signalOutboxWork()
	sealdicelogger.M().Infof("群组本地数据删除完成: group=%s dice=%v scopes=%v deleted=%+v", canonical.GroupID, canonical.DiceIDs, canonical.Scopes, result.Deleted)
	return result, nil
}
func (s *GORMStore) advancePrivacyCatalog(tx *gorm.DB, resource revisionResourceKey) error {
	var row revisionHeadRow
	if err := revisionQuery(tx, resource.kind, resource.scope, resource.member).Take(&row).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		seed := revisionRow(resource, 1, true, s.task5Now())
		return tx.Create(&seed).Error
	}
	revision, err := nextVersion(row.Revision)
	if err != nil {
		return err
	}
	return tx.Model(&revisionHeadRow{}).Where("id = ?", row.ID).Updates(map[string]any{"revision": revision, "updated_at": s.task5Now()}).Error
}
