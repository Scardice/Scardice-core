package eventstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	PrivacyBatchRecords = 500
	PrivacyBatchBytes   = 8 * 1024 * 1024
	privacyFenceScope   = "group"
)

var _ PrivacyHistoryRepository = (*GORMStore)(nil)
var _ PrivacySubjectKeyResolver = (*GORMStore)(nil)

func privacyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"group_record"}, nil
	}
	seen := map[string]bool{}
	for _, raw := range scopes {
		scope := strings.TrimSpace(raw)
		if scope != "group_record" && scope != "players" && scope != "attrs" && scope != "logs" {
			return nil, ErrInvalidMetadata
		}
		seen[scope] = true
	}
	out := make([]string, 0, len(seen))
	for _, scope := range []string{"group_record", "players", "attrs", "logs"} {
		if seen[scope] {
			out = append(out, scope)
		}
	}
	return out, nil
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

func privacySubjectKey(ctx context.Context, s *GORMStore, groupID string) ([]byte, error) {
	if strings.TrimSpace(groupID) == "" {
		return nil, ErrInvalidMetadata
	}
	return s.privacyHMAC(ctx, "privacy-subject/v1", groupID)
}

// PrivacySubjectKey resolves the privacy-subject/v1 HMAC used by group
// attribute events and privacy fences.
func (s *GORMStore) PrivacySubjectKey(ctx context.Context, groupID string) ([]byte, error) {
	return privacySubjectKey(ctx, s, groupID)
}

func privacyHMACWithMaterial(material []byte, domain string, parts ...string) ([]byte, error) {
	if len(material) != sha256.Size {
		return nil, ErrKeySourceUnavailable
	}
	mac := hmac.New(sha256.New, material)
	mac.Write([]byte(domain))
	for _, part := range parts {
		mac.Write([]byte(part))
	}
	return mac.Sum(nil), nil
}

func (s *GORMStore) privacyHMAC(ctx context.Context, domain string, parts ...string) ([]byte, error) {
	if s == nil || s.keySource == nil {
		return nil, ErrKeySourceUnavailable
	}
	_, material, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return nil, err
	}
	return privacyHMACWithMaterial(material, domain, parts...)
}

func privacyLikePrefix(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value) + `%`
}

func privacyDecodeAttributeSnapshot(row domainEventRow) (diceID, id, attrsType, secretRef string, ok bool) {
	parts, valid := privacyDecodeParts(row.AggregateID, 2)
	if !valid {
		return "", "", "", "", false
	}
	var snapshot struct {
		DiceID    string `json:"diceId"`
		ID        string `json:"id"`
		AttrsType string `json:"attrsType"`
		SecretRef string `json:"secretRef"`
	}
	if err := json.Unmarshal(row.Payload, &snapshot); err != nil ||
		snapshot.DiceID != parts[0] || snapshot.ID != parts[1] {
		return "", "", "", "", false
	}
	return snapshot.DiceID, snapshot.ID, snapshot.AttrsType, snapshot.SecretRef, true
}

type privacyGroupUserPrefix struct {
	group string
	user  string
}

var privacyGroupUserPrefixes = [...]privacyGroupUserPrefix{
	{"QQ-Group:", "QQ:"},
	{"QQ-CH-Group:", "QQ-CH:"},
	{"KOOK-CH-Group:", "KOOK:"},
	{"DODO-Group:", "DODO:"},
	{"TG-Group:", "TG:"},
	{"DISCORD-CH-Group:", "DISCORD:"},
	{"SEALCHAT-Group:", "SEALCHAT:"},
	{"SLACK-CH-Group", "SLACK:"},
	{"DINGTALK-Group", "DINGTALK:"},
	{"OpenQQCH-Channel:", "OpenQQCH:"},
	{"OpenQQ-Group-T:", "OpenQQ-Member-T:"},
	{"UI-Group:", "UI:"},
	{"PG-QQ:", "QQ:"},
	{"PG-KOOK:", "KOOK:"},
	{"PG-SEALCHAT:", "SEALCHAT:"},
	{"PG-UI:", "UI:"},
	{"PG-DISCORD:", "DISCORD:"},
	{"PG-DODO:", "DODO:"},
	{"PG-SLACK:", "SLACK:"},
	{"PG-TG:", "TG:"},
	{"PG-DINGTALK:", "DINGTALK:"},
	{"PG-OpenQQCH:", "OpenQQCH:"},
}

var privacyDirectGroupPrefixes = [...]string{
	"QQ-Group:", "QQ-CH-Group:", "KOOK-CH-Group:", "DODO-Group:",
	"TG-Group:", "DISCORD-CH-Group:", "SEALCHAT-Group:", "UI-Group:",
	"SLACK-CH-Group", "DINGTALK-Group", "OpenQQ-Group-T:",
	"OpenQQCH-Channel:",
	"PG-QQ:", "PG-KOOK:", "PG-SEALCHAT:", "PG-UI:", "PG-DISCORD:",
	"PG-DODO:", "PG-SLACK:", "PG-TG:", "PG-DINGTALK:",
	"PG-OpenQQCH:",
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

func privacyGroupAttributeIdentity(id, attrsType string) (groupID string, groupLike bool, scoped bool) {
	if attrsType == "group_user" {
		if groupID, ok := privacyGroupUserOwner(id); ok {
			return groupID, true, true
		}
		return "", true, false
	}
	if groupID, ok := privacyGroupUserOwner(id); ok {
		return groupID, true, true
	}
	for _, prefix := range privacyDirectGroupPrefixes {
		if strings.HasPrefix(id, prefix) {
			return id, true, true
		}
	}
	if attrsType == "group" {
		return id, true, true
	}
	return "", false, false
}

func privacyRecordSelection(row domainEventRow, req PrivacyDryRunRequest) (selected, ambiguous bool) {
	if row.AggregateType != "attributes" {
		return true, false
	}
	diceID, id, attrsType, _, ok := privacyDecodeAttributeSnapshot(row)
	if !ok {
		return false, false
	}
	matchedDice := false
	for _, candidate := range req.DiceIDs {
		if candidate == diceID {
			matchedDice = true
			break
		}
	}
	if !matchedDice {
		return false, false
	}
	groupID, groupLike, scoped := privacyGroupAttributeIdentity(id, attrsType)
	if groupLike && scoped {
		return groupID == req.GroupID, false
	}
	ambiguous = attrsType == "group_user" && groupLike && !scoped &&
		(id == req.GroupID || strings.HasPrefix(id, req.GroupID+"-"))
	return false, ambiguous
}

func privacyHasGroupAttrsPayload(row domainEventRow) bool {
	if row.AggregateType != "attributes" {
		return false
	}
	var snapshot struct {
		AttrsType string `json:"attrsType"`
	}
	if err := json.Unmarshal(row.Payload, &snapshot); err != nil {
		return false
	}
	return snapshot.AttrsType == "group" || snapshot.AttrsType == "group_user"
}

func privacyRejectUnkeyedGroupAttrs(ctx context.Context, tx *gorm.DB) error {
	var fencedCount int64
	if err := tx.WithContext(ctx).Model(&subjectFenceRow{}).Where("scope = ?", privacyFenceScope).Count(&fencedCount).Error; err != nil {
		return ErrParticipantFailure
	}
	if fencedCount > 0 {
		return ErrInvalidTransition
	}
	return nil
}

func privacyCheckSubjectFence(ctx context.Context, tx *gorm.DB, subjectKey []byte) error {
	var row subjectFenceRow
	err := tx.WithContext(ctx).Where("subject_key = ? AND scope = ?", subjectKey, privacyFenceScope).First(&row).Error
	if err == nil {
		return ErrInvalidTransition
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	return nil
}
func privacyConditions(req PrivacyDryRunRequest) (string, []any, error) {
	scopes, err := privacyScopes(req.Scopes)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(req.GroupID) == "" || len(req.DiceIDs) == 0 {
		return "", nil, ErrInvalidMetadata
	}
	dice := append([]string(nil), req.DiceIDs...)
	sort.Strings(dice)
	clauses, args := make([]string, 0, len(scopes)*len(dice)*2), make([]any, 0, len(scopes)*len(dice)*4)
	for _, d := range dice {
		if strings.TrimSpace(d) == "" {
			return "", nil, ErrInvalidMetadata
		}
		groupID := privacyCanonical(d, req.GroupID)
		for _, scope := range scopes {
			switch scope {
			case "group_record":
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id = ?)")
				args = append(args, "group", groupID)
			case "players":
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id LIKE ? ESCAPE '\\')")
				args = append(args, "player", privacyLikePrefix(privacyCanonical(d, req.GroupID)))
			case "attrs":
				clauses = append(clauses, "((aggregate_type = ? OR aggregate_type = ?) AND (aggregate_id = ? OR aggregate_id LIKE ? ESCAPE '\\'))")
				args = append(args, "attrs/group", "attrs/group-user", groupID, privacyLikePrefix(privacyCanonical(d, req.GroupID)))
				clauses = append(clauses, "(aggregate_type = ? AND aggregate_id LIKE ? ESCAPE '\\')")
				args = append(args, "attributes", privacyLikePrefix(privacyCanonical(d)))
			case "logs":
				// Story-log rows are selected through keyed scope indexes.
			}
		}
	}
	if len(clauses) == 0 {
		return "1 = 0", nil, nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args, nil
}

func (s *GORMStore) PrivacyDryRun(ctx context.Context, req PrivacyDryRunRequest) (PrivacyDryRunResult, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return PrivacyDryRunResult{}, ErrParticipantFailure
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return PrivacyDryRunResult{}, err
	}
	scopes, queryErr := privacyScopes(req.Scopes)
	if queryErr != nil {
		return PrivacyDryRunResult{}, queryErr
	}
	req.Scopes = scopes
	condition, args, queryErr := privacyConditions(req)
	if queryErr != nil {
		return PrivacyDryRunResult{}, queryErr
	}
	counts := PrivacyCounts{}
	var maxPosition, cursor uint64
	dataHash := sha256.New()
	for {
		var rows []domainEventRow
		queryArgs := append(append([]any(nil), args...), cursor)
		if err := s.db.GORM().WithContext(ctx).Select("aggregate_type", "aggregate_id", "global_position", "payload", "checksum").Where(condition+" AND global_position > ?", queryArgs...).Order("global_position ASC").Limit(PrivacyBatchRecords).Find(&rows).Error; err != nil {
			return PrivacyDryRunResult{}, ErrParticipantFailure
		}
		for _, row := range rows {
			selected, ambiguous := privacyRecordSelection(row, req)
			if ambiguous {
				return PrivacyDryRunResult{}, ErrInvalidMetadata
			}
			if !selected {
				continue
			}
			if row.GlobalPosition > maxPosition {
				maxPosition = row.GlobalPosition
			}
			writeCanonicalString(dataHash, row.AggregateType)
			writeCanonicalString(dataHash, row.AggregateID)
			writeCanonicalUint64(dataHash, row.GlobalPosition)
			writeCanonicalBytes(dataHash, row.Payload, row.Payload == nil)
			writeCanonicalBytes(dataHash, row.Checksum, row.Checksum == nil)
			switch row.AggregateType {
			case "group":
				counts.GroupRecord++
			case "player":
				counts.Players++
			case "attrs/group", "attrs/group-user", "attributes":
				counts.Attrs++
			}
		}
		if len(rows) < PrivacyBatchRecords {
			break
		}
		cursor = rows[len(rows)-1].GlobalPosition
	}
	if privacyHasLogScope(scopes) {
		selection, err := s.privacyLogArchiveSelection(ctx, req.GroupID, req.DiceIDs)
		if err != nil {
			return PrivacyDryRunResult{}, err
		}
		if err := privacyWriteStoryLogArchiveDigest(ctx, s.db.GORM(), selection, dataHash, &counts); err != nil {
			return PrivacyDryRunResult{}, err
		}
	}
	active := append([]string(nil), req.ActiveDiceIDs...)
	sort.Strings(active)
	canonical := fmt.Sprintf("privacy-dry-run/v2|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%x|active=%t|%s", req.GroupID, strings.Join(scopes, ","), maxPosition, counts.GroupRecord, counts.Players, counts.Attrs, counts.LogSessions, counts.LogStates, counts.LogEntries, counts.LogIntents, counts.LogImports, dataHash.Sum(nil), req.ActiveDiceIDs != nil, strings.Join(active, ","))
	var canonicalSb170 strings.Builder
	for _, d := range append([]string(nil), req.DiceIDs...) {
		canonicalSb170.WriteString("|" + d)
	}
	canonical += canonicalSb170.String()
	digest, queryErr := s.privacyHMAC(ctx, "privacy-confirmation/v1", canonical)
	if queryErr != nil {
		return PrivacyDryRunResult{}, queryErr
	}
	keyID, _, queryErr := keySourceIndex(ctx, s.keySource)
	if queryErr != nil {
		return PrivacyDryRunResult{}, queryErr
	}
	subjectKey, queryErr := privacySubjectKey(ctx, s, req.GroupID)
	if queryErr != nil {
		return PrivacyDryRunResult{}, queryErr
	}
	var sequence eventGlobalSequenceRow
	if err := s.db.GORM().WithContext(ctx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		return PrivacyDryRunResult{}, ErrParticipantFailure
	}
	targetHighWater := uint64(0)
	if sequence.NextPosition > 0 {
		targetHighWater = sequence.NextPosition - 1
	}
	uncovered := []string{"legacy GroupInfo", "legacy GroupPlayerInfo", "legacy group/attrs tables", "moderation", "encrypted plugin KV"}
	if !privacyHasLogScope(scopes) {
		uncovered = append(uncovered, "logs")
	}
	uncovered = append(uncovered, "user-global characters", "external stores", "backups")
	return PrivacyDryRunResult{Version: maxPosition, TargetHighWater: targetHighWater, Digest: digest, DigestKeyID: keyID, SubjectKey: subjectKey, Counts: counts, ActiveDiceIDs: active, Uncovered: uncovered}, nil
}

func marshalPrivacyContext(v PrivacyOperationContext) ([]byte, error) { return json.Marshal(v) }
func unmarshalPrivacyContext(b []byte) (PrivacyOperationContext, error) {
	var v PrivacyOperationContext
	if len(b) == 0 {
		return v, ErrNotFound
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return v, ErrAuthenticationFailed
	}
	return v, nil
}
func (s *GORMStore) PrivacyCreateOperation(ctx context.Context, operationID string, subjectKey []byte, private PrivacyOperationContext) error {
	if len(subjectKey) != sha256.Size || strings.TrimSpace(operationID) == "" {
		return ErrInvalidMetadata
	}
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	plain, err := marshalPrivacyContext(private)
	if err != nil {
		return ErrInvalidMetadata
	}
	owner := fmt.Sprintf("hmac:%x", subjectKey)
	cipherText, nonce, keyID, err := a6Seal(ctx, s.keySource, "operation-private/v1", operationID, owner, 1, plain)
	if err != nil {
		return err
	}
	_, err = s.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: operationID, ExpectedVersion: 0, Version: 1, Kind: "privacy-purge", Status: "pending", PrincipalID: owner, IdempotencyScope: "privacy-purge", IdempotencyKey: operationID, PrivateContextCiphertext: cipherText, PrivateContextNonce: nonce, EncryptionKeyID: keyID}}})
	return err
}

func hexBytes(value []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = hex[b>>4], hex[b&15]
	}
	return string(out)
}

func (s *GORMStore) PrivacyLoadOperation(ctx context.Context, operationID string) (OperationView, PrivacyOperationContext, error) {
	var row operationRow
	if err := s.db.GORM().WithContext(ctx).Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return OperationView{}, PrivacyOperationContext{}, ErrNotFound
		}
		return OperationView{}, PrivacyOperationContext{}, ErrParticipantFailure
	}
	view := OperationView{OperationID: row.OperationID, Version: row.Version, Kind: row.Kind, Status: row.Status, ResultCode: row.ResultCode, ErrorCode: row.ErrorCode, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ExpiresAt: valueTime(row.ExpiresAt)}
	if len(row.PrivateContext) == 0 && (row.Status == "completed" || row.Status == "completed-uncovered" || row.Status == "cancelled") {
		return view, PrivacyOperationContext{}, nil
	}
	plain, err := a6Open(ctx, s.keySource, "operation-private/v1", operationID, row.PrincipalID, row.Version, row.PrivateKeyID, row.PrivateContext, row.PrivateNonce)
	if err != nil {
		return OperationView{}, PrivacyOperationContext{}, err
	}
	private, err := unmarshalPrivacyContext(plain)
	if err != nil {
		return OperationView{}, PrivacyOperationContext{}, err
	}
	return view, private, nil
}

func (s *GORMStore) PrivacyVerifyOperationSubject(ctx context.Context, operationID, groupID string) error {
	var row operationRow
	if err := s.db.GORM().WithContext(ctx).Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		return ErrNotFound
	}
	subject, err := privacySubjectKey(ctx, s, groupID)
	if err != nil {
		return err
	}
	if row.PrincipalID != fmt.Sprintf("hmac:%x", subject) {
		return ErrAuthenticationFailed
	}
	return nil
}

func (s *GORMStore) PrivacyUpdateOperation(ctx context.Context, operationID string, expected uint64, private PrivacyOperationContext, status string) (uint64, error) {
	var row operationRow
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return 0, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := tx.Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrNotFound
		}
		return 0, ErrParticipantFailure
	}
	if row.Version != expected {
		return 0, ErrParticipantConflict
	}
	next, err := nextVersion(row.Version)
	if err != nil {
		return 0, err
	}
	plain, err := marshalPrivacyContext(private)
	if err != nil {
		return 0, ErrInvalidMetadata
	}
	cipherText, nonce, keyID, err := a6Seal(ctx, s.keySource, "operation-private/v1", operationID, row.PrincipalID, next, plain)
	if err != nil {
		return 0, err
	}
	updates := map[string]any{"version": next, "status": status, "private_context": cipherText, "private_nonce": nonce, "private_key_id": keyID, "private_payload_version": next, "updated_at": s.task5Now()}
	if tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?", operationID, expected).Updates(updates).RowsAffected != 1 {
		return 0, ErrParticipantConflict
	}
	if err := tx.Commit().Error; err != nil {
		return 0, ErrParticipantFailure
	}
	return next, nil
}

func (s *GORMStore) PrivacyFence(ctx context.Context, subjectKey []byte, scope, operationID string) (uint64, error) {
	if len(subjectKey) != sha256.Size || operationID == "" || scope == "" {
		return 0, ErrInvalidMetadata
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return 0, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return 0, err
	}
	var operation operationRow
	if err := tx.Where("operation_id = ?", operationID).First(&operation).Error; err != nil {
		return 0, ErrNotFound
	}
	if operation.PrincipalID != fmt.Sprintf("hmac:%x", subjectKey) || operation.Kind != "privacy-purge" {
		return 0, ErrAuthenticationFailed
	}
	var fence subjectFenceRow
	q := tx.Where("subject_key = ? AND scope = ?", subjectKey, scope).First(&fence)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		fence = subjectFenceRow{SubjectKey: append([]byte(nil), subjectKey...), Scope: scope, Version: 1, PurgeOperationID: operationID, CreatedAt: s.task5Now()}
		if err := tx.Create(&fence).Error; err != nil {
			return 0, ErrParticipantConflict
		}
		if err := tx.Commit().Error; err != nil {
			return 0, ErrParticipantFailure
		}
		return 1, nil
	}
	if q.Error != nil {
		return 0, ErrParticipantFailure
	}
	if fence.PurgeOperationID != operationID {
		return 0, ErrParticipantConflict
	}
	if err := tx.Commit().Error; err != nil {
		return 0, ErrParticipantFailure
	}
	return fence.Version, nil
}
func (s *GORMStore) PrivacyFenceVersion(ctx context.Context, subjectKey []byte, scope string) (uint64, error) {
	var row subjectFenceRow
	err := s.db.GORM().WithContext(ctx).Where("subject_key = ? AND scope = ?", subjectKey, scope).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, ErrParticipantFailure
	}
	return row.Version, nil
}
func (s *GORMStore) PrivacyUnfence(ctx context.Context, subjectKey []byte, scope string, expected uint64, operationID string) error {
	_, err := s.Commit(ctx, UnitOfWork{FenceUpdates: []SubjectFenceUpdate{{SubjectKey: subjectKey, Scope: scope, ExpectedVersion: expected, PurgeOperationID: operationID, Deleted: true}}})
	return err
}

func (s *GORMStore) PrivacyResolvePending(ctx context.Context, subjectKey []byte, operationID string) error {
	if len(subjectKey) != sha256.Size || strings.TrimSpace(operationID) == "" {
		return ErrInvalidMetadata
	}
	now := s.task5Now()
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	var operation operationRow
	if err := tx.Where("operation_id = ? AND principal_id = ? AND kind = ?", operationID, fmt.Sprintf("hmac:%x", subjectKey), "privacy-purge").First(&operation).Error; err != nil {
		return ErrAuthenticationFailed
	}
	inboxStatuses := []string{InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous}
	var inboxRows []inboxMessageRow
	if err := tx.Where("subject_key = ? AND status IN ?", subjectKey, inboxStatuses).Find(&inboxRows).Error; err != nil {
		return ErrParticipantFailure
	}
	for _, row := range inboxRows {
		next, err := nextVersion(row.Version)
		if err != nil {
			return err
		}
		row.Version, row.Status, row.LeaseOwner, row.AttemptID = next, InboxStatusSkipped, "", ""
		row.LeaseEpoch, row.LeaseExpiry, row.CompletedAt = 0, nil, task5Ptr(now)
		row.PayloadCiphertext, row.PayloadNonce, row.ContentDigest = nil, nil, nil
		row.EncryptionKeyID, row.ContentDigestKeyID, row.ResolutionReason = "", "", "privacy purge"
		row.ResolutionPrincipal, row.ResolutionAt = "privacy-purge", task5Ptr(now)
		if q := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, next-1).Updates(inboxMap(row)); q.Error != nil || q.RowsAffected != 1 {
			return ErrParticipantConflict
		}
	}
	outboxStatuses := []string{OutboxStatusPending, OutboxStatusLeased, OutboxStatusAmbiguous, OutboxStatusDispatched}
	var outboxRows []outboxEffectRow
	if err := tx.Where("subject_key = ? AND status IN ?", subjectKey, outboxStatuses).Find(&outboxRows).Error; err != nil {
		return ErrParticipantFailure
	}
	for _, row := range outboxRows {
		next, err := nextVersion(row.Version)
		if err != nil {
			return err
		}
		row.Version, row.Status, row.LeaseOwner, row.AttemptID = next, OutboxStatusFailed, "", ""
		row.LeaseEpoch, row.LeaseExpiry, row.CompletedAt = 0, nil, task5Ptr(now)
		row.PayloadCiphertext, row.PayloadNonce, row.ContentDigest = nil, nil, nil
		row.EncryptionKeyID, row.ContentDigestKeyID, row.ResolutionReason = "", "", "privacy purge"
		row.ResolutionPrincipal, row.ResolutionAt, row.ScrubbedAt = "privacy-purge", task5Ptr(now), task5Ptr(now)
		if q := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, next-1).Updates(outboxMap(row)); q.Error != nil || q.RowsAffected != 1 {
			return ErrParticipantConflict
		}
	}
	refs := make([]queueLaneRef, 0, len(inboxRows)+len(outboxRows))
	for _, row := range inboxRows {
		refs = append(refs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
	}
	for _, row := range outboxRows {
		refs = append(refs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
	}
	if err := refreshQueueLaneRefs(tx, refs, now); err != nil {
		return ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func privacyBatchCondition(req PrivacyBatchRequest) (string, []any, error) {
	return privacyConditions(PrivacyDryRunRequest{GroupID: req.GroupID, DiceIDs: req.DiceIDs, Scopes: req.Scopes})
}
func (s *GORMStore) PrivacyDeleteBatch(ctx context.Context, req PrivacyBatchRequest) (PrivacyBatchResult, error) {
	if err := s.requireReady(ctx); err != nil {
		return PrivacyBatchResult{}, err
	}
	opView, private, opErr := s.PrivacyLoadOperation(ctx, req.OperationID)
	canonicalScopes, scopeErr := privacyScopes(req.Scopes)
	requestDice, storedDice := append([]string(nil), req.DiceIDs...), append([]string(nil), private.DiceIDs...)
	sort.Strings(requestDice)
	sort.Strings(storedDice)
	if opErr != nil || scopeErr != nil || private.GroupID != req.GroupID || private.Phase != "delete" || req.Phase != "delete" || opView.Kind != "privacy-purge" || (opView.Status != "pending" && opView.Status != "running" && opView.Status != "resumable-failure") || strings.Join(canonicalScopes, ",") != strings.Join(private.Scopes, ",") || strings.Join(requestDice, ",") != strings.Join(storedDice, ",") {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	subjectKey, subjectErr := privacySubjectKey(ctx, s, req.GroupID)
	if subjectErr != nil {
		return PrivacyBatchResult{}, subjectErr
	}
	fenceVersion, fenceErr := s.PrivacyFenceVersion(ctx, subjectKey, privacyFenceScope)
	if fenceErr != nil || fenceVersion == 0 {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	var fence subjectFenceRow
	if err := s.db.GORM().WithContext(ctx).Where("subject_key = ? AND scope = ? AND version = ? AND purge_operation_id = ?", subjectKey, privacyFenceScope, fenceVersion, req.OperationID).First(&fence).Error; err != nil {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	if req.Limit <= 0 || req.Limit > PrivacyBatchRecords {
		req.Limit = PrivacyBatchRecords
	}
	cond, args, err := privacyBatchCondition(req)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	if req.Cursor != private.Cursor {
		return PrivacyBatchResult{}, ErrParticipantConflict
	}
	archiveCursor, archiveStage, err := decodePrivacyLogArchiveCursor(req.Cursor)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	logsSelected := privacyHasLogScope(canonicalScopes)
	if archiveStage && !logsSelected {
		return PrivacyBatchResult{}, ErrInvalidMetadata
	}
	var archiveSelection privacyLogArchiveSelection
	if logsSelected {
		archiveSelection, err = s.privacyLogArchiveSelection(ctx, req.GroupID, req.DiceIDs)
		if err != nil {
			return PrivacyBatchResult{}, err
		}
	}
	cursor := uint64(0)
	if !archiveStage && strings.TrimSpace(req.Cursor) != "" {
		cursor, err = strconv.ParseUint(req.Cursor, 10, 64)
		if err != nil {
			return PrivacyBatchResult{}, ErrInvalidMetadata
		}
	}
	var rows []domainEventRow
	pageLimit := PrivacyBatchBytes / MaxEventPayloadBytes
	if pageLimit < 1 {
		pageLimit = 1
	}
	pageCursor, sourceDone := cursor, archiveStage
	totalBytes := 0
	selection := PrivacyDryRunRequest{GroupID: req.GroupID, DiceIDs: req.DiceIDs}
	for len(rows) < req.Limit && !sourceDone {
		var page []domainEventRow
		q := s.db.GORM().WithContext(ctx).Select("event_id", "aggregate_type", "aggregate_id", "global_position", "payload").Where(cond+" AND global_position > ?", append(args, pageCursor)...).Order("global_position ASC").Limit(pageLimit).Find(&page)
		if q.Error != nil {
			return PrivacyBatchResult{}, ErrParticipantFailure
		}
		if len(page) == 0 {
			sourceDone = true
			break
		}
		consumed, stopped := 0, false
		for _, row := range page {
			selected, ambiguous := privacyRecordSelection(row, selection)
			if ambiguous {
				return PrivacyBatchResult{}, ErrInvalidMetadata
			}
			if !selected {
				pageCursor = row.GlobalPosition
				consumed++
				continue
			}
			if len(rows) > 0 && totalBytes+len(row.Payload) > PrivacyBatchBytes {
				stopped = true
				break
			}
			rows = append(rows, row)
			totalBytes += len(row.Payload)
			pageCursor = row.GlobalPosition
			consumed++
			if len(rows) == req.Limit {
				stopped = true
				break
			}
		}
		if stopped {
			sourceDone = len(page) < pageLimit && consumed == len(page)
			break
		}
		sourceDone = len(page) < pageLimit && consumed == len(page)
		if consumed < len(page) {
			sourceDone = false
			break
		}
	}
	if len(rows) == 0 {
		if sourceDone && logsSelected {
			if !archiveStage {
				archiveCursor = privacyLogArchiveCursor{Table: privacyLogSessionsTable}
			}
			return s.privacyDeleteLogArchiveBatch(ctx, req, subjectKey, fenceVersion, opView, private, archiveSelection, archiveCursor, req.Limit)
		}
		nextCursor := req.Cursor
		if pageCursor != cursor {
			nextCursor = strconv.FormatUint(pageCursor, 10)
		}
		return PrivacyBatchResult{NextCursor: nextCursor, Done: sourceDone}, nil
	}
	selected := rows
	ids := make([]string, len(selected))
	tombstones := make([]eventTombstoneRow, len(selected))
	counts := PrivacyCounts{}
	for i, row := range selected {
		ids[i] = row.EventID
		tombstones[i].GlobalPosition = row.GlobalPosition
		switch row.AggregateType {
		case "group":
			counts.GroupRecord++
		case "player":
			counts.Players++
		case "attrs/group", "attrs/group-user", "attributes":
			counts.Attrs++
		}
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return PrivacyBatchResult{}, err
	}
	var liveFence subjectFenceRow
	if err := tx.Where("subject_key = ? AND scope = ? AND purge_operation_id = ?", subjectKey, privacyFenceScope, req.OperationID).First(&liveFence).Error; err != nil {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	var liveOperation operationRow
	if err := tx.Where("operation_id = ? AND status IN ?", req.OperationID, []string{"pending", "running", "resumable-failure"}).First(&liveOperation).Error; err != nil {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	if liveOperation.Version != opView.Version || liveOperation.PrincipalID != fmt.Sprintf("hmac:%x", subjectKey) {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	lockedPlain, lockErr := a6Open(ctx, s.keySource, "operation-private/v1", req.OperationID, liveOperation.PrincipalID, liveOperation.Version, liveOperation.PrivateKeyID, liveOperation.PrivateContext, liveOperation.PrivateNonce)
	if lockErr != nil {
		return PrivacyBatchResult{}, lockErr
	}
	lockedPrivate, lockErr := unmarshalPrivacyContext(lockedPlain)
	if lockErr != nil {
		return PrivacyBatchResult{}, lockErr
	}
	if lockedPrivate.Phase != "delete" || lockedPrivate.GroupID != req.GroupID || lockedPrivate.Cursor != req.Cursor || strings.Join(lockedPrivate.DiceIDs, "\x00") != strings.Join(private.DiceIDs, "\x00") || strings.Join(lockedPrivate.Scopes, "\x00") != strings.Join(private.Scopes, "\x00") {
		return PrivacyBatchResult{}, ErrParticipantConflict
	}
	if req.Phase != "delete" {
		return PrivacyBatchResult{}, ErrInvalidTransition
	}
	var control projectionControlRow
	if err := tx.Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	revision, err := nextVersion(control.HistoryRevision)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	deleted := tx.Where("event_id IN ?", ids).Delete(&domainEventRow{})
	if deleted.Error != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return PrivacyBatchResult{}, ErrParticipantConflict
	}
	if err := tx.Create(&tombstones).Error; err != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("history_revision", revision).Error; err != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	// Remove heads, read models, and attribute secrets only after the final
	// event for a selected stream has been removed.
	for _, row := range selected {
		var left int64
		if err := tx.Model(&domainEventRow{}).Where("aggregate_type = ? AND aggregate_id = ?", row.AggregateType, row.AggregateID).Count(&left).Error; err != nil {
			return PrivacyBatchResult{}, ErrParticipantFailure
		}
		if left != 0 {
			continue
		}
		if err := tx.Where("aggregate_type = ? AND aggregate_id = ?", row.AggregateType, row.AggregateID).Delete(&aggregateHeadRow{}).Error; err != nil {
			return PrivacyBatchResult{}, ErrParticipantFailure
		}
		projections := tx.Where("row_key = ?", row.AggregateID)
		if row.AggregateType == "attributes" {
			projections = projections.Where("projection_name = ?", "attributes")
		}
		if err := projections.Delete(&projectionReadModelRow{}).Error; err != nil {
			return PrivacyBatchResult{}, ErrParticipantFailure
		}
		if row.AggregateType == "attributes" {
			_, id, _, secretRef, ok := privacyDecodeAttributeSnapshot(row)
			if ok && secretRef != "" {
				if err := tx.Where("secret_ref = ? AND endpoint_id = ? AND adapter_id = ?", secretRef, id, "attributes").Delete(&adapterSecretRow{}).Error; err != nil {
					return PrivacyBatchResult{}, ErrParticipantFailure
				}
			}
		}
	}
	if err := tx.Commit().Error; err != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	nextCursor := strconv.FormatUint(pageCursor, 10)
	done := sourceDone
	if sourceDone && logsSelected {
		nextCursor = encodePrivacyLogArchiveCursor(privacyLogArchiveCursor{Table: privacyLogSessionsTable})
		done = false
	}
	return PrivacyBatchResult{NextCursor: nextCursor, Deleted: counts, Done: done}, nil
}

func (s *GORMStore) PrivacyRebuildPublish(ctx context.Context, targetHighWater uint64) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	s.projectorMu.RLock()
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	setVersion := projectorSetVersion(projectors)
	s.projectorMu.RUnlock()
	if len(projectors) == 0 {
		return ErrInvalidProjector
	}
	base := s.db.GORM().WithContext(ctx)
	var source projectionControlRow
	if err := base.Where("singleton_id = ?", "default").First(&source).Error; err != nil {
		return ErrParticipantFailure
	}
	highWater, err := s.highWater(ctx)
	if err != nil {
		return err
	}
	if highWater != targetHighWater {
		return ErrParticipantConflict
	}
	generation, err := (UUIDGenerator{}).NewID()
	if err != nil {
		return ErrParticipantFailure
	}
	var cursor uint64
	for cursor < targetHighWater {
		rows, err := loadProjectionEventPage(base, cursor, targetHighWater)
		if err != nil {
			return err
		}
		next, err := validateProjectionPage(base, rows, cursor, targetHighWater)
		if err != nil {
			return err
		}
		if err := s.applyProjectionPage(ctx, generation, &source, rows, projectors); err != nil {
			return err
		}
		cursor = next
	}
	s.projectorMu.RLock()
	defer s.projectorMu.RUnlock()
	tx := base.Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	if err := validateProjectionSource(tx, &source); err != nil {
		return err
	}
	if err := validateProjectionRows(tx, generation); err != nil {
		return ErrProjectionInvariant
	}
	if _, err := digestProjectionRows(tx, generation); err != nil {
		return ErrProjectionInvariant
	}
	liveSetVersion := projectorSetVersion(s.projectors)
	if liveSetVersion != setVersion {
		return ErrParticipantConflict
	}
	var sequence eventGlobalSequenceRow
	if err := tx.Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		return ErrParticipantFailure
	}
	current := uint64(0)
	if sequence.NextPosition > 0 {
		current = sequence.NextPosition - 1
	}
	if current != targetHighWater {
		return ErrParticipantConflict
	}
	if err := tx.Where("projection_generation <> ?", generation).Delete(&projectionReadModelRow{}).Error; err != nil {
		return ErrParticipantFailure
	}
	if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{"active_generation": generation, "terminal_position": cursor, "projector_set_version": setVersion, "publication_state": "published", "updated_at": s.task5Now()}).Error; err != nil {
		return ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
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

func privacyStreamGroupID(stream StreamID) string {
	switch stream.AggregateType {
	case "group", "player", "attrs/group", "attrs/group-user", "moderation/group":
		parts, ok := privacyDecodeParts(stream.AggregateID, 3)
		if ok && stream.AggregateType != "group" && stream.AggregateType != "attrs/group" {
			return parts[1]
		}
		parts, ok = privacyDecodeParts(stream.AggregateID, 2)
		if ok {
			return parts[1]
		}
	}
	return ""
}

func (s *GORMStore) privacyRejectFencedStreams(ctx context.Context, tx *gorm.DB, streams []StreamAppend) error {
	if s == nil {
		return nil
	}
	for _, appendStream := range streams {
		if appendStream.Stream.AggregateType == "attributes" {
			for _, event := range appendStream.Events {
				row := domainEventRow{
					AggregateType: appendStream.Stream.AggregateType,
					AggregateID:   appendStream.Stream.AggregateID,
					Payload:       event.Payload,
				}
				_, id, attrsType, _, valid := privacyDecodeAttributeSnapshot(row)
				groupID, groupLike, scoped := privacyGroupAttributeIdentity(id, attrsType)
				if valid && groupLike {
					if !scoped {
						if len(event.Metadata.SubjectKey) > 0 {
							return ErrInvalidMetadata
						}
						if err := privacyRejectUnkeyedGroupAttrs(ctx, tx); err != nil {
							return err
						}
						continue
					}
					switch len(event.Metadata.SubjectKey) {
					case 0:
						if err := privacyRejectUnkeyedGroupAttrs(ctx, tx); err != nil {
							return err
						}
					case sha256.Size:
						subjectKey, err := privacySubjectKey(ctx, s, groupID)
						if err != nil {
							return err
						}
						if !hmac.Equal(event.Metadata.SubjectKey, subjectKey) {
							return ErrInvalidMetadata
						}
						if err := privacyCheckSubjectFence(ctx, tx, subjectKey); err != nil {
							return err
						}
					default:
						return ErrInvalidMetadata
					}
					continue
				}
				if len(event.Metadata.SubjectKey) > 0 {
					return ErrInvalidMetadata
				}
				if privacyHasGroupAttrsPayload(row) {
					if err := privacyRejectUnkeyedGroupAttrs(ctx, tx); err != nil {
						return err
					}
				}
			}
			continue
		}
		if s.keySource == nil {
			continue
		}
		if appendStream.Stream.AggregateType == "outbound-effect" {
			for _, event := range appendStream.Events {
				if len(event.Metadata.SubjectKey) != sha256.Size {
					var fencedCount int64
					if err := tx.Model(&subjectFenceRow{}).Where("scope = ?", privacyFenceScope).Count(&fencedCount).Error; err != nil {
						return ErrParticipantFailure
					}
					if fencedCount > 0 {
						return ErrInvalidTransition
					}
					continue
				}
				if err := privacyCheckSubjectFence(ctx, tx, event.Metadata.SubjectKey); err != nil {
					return err
				}
			}
		}
		groupID := privacyStreamGroupID(appendStream.Stream)
		if groupID == "" {
			continue
		}
		subject, err := privacySubjectKey(ctx, s, groupID)
		if err != nil {
			return err
		}
		if err := privacyCheckSubjectFence(ctx, tx, subject); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) PrivacyScrubOperation(ctx context.Context, operationID string, expected uint64) error {
	next, err := nextVersion(expected)
	if err != nil {
		return err
	}
	q := s.db.GORM().WithContext(ctx).Model(&operationRow{}).Where("operation_id = ? AND version = ?", operationID, expected).Updates(map[string]any{"version": next, "private_context": nil, "private_nonce": nil, "private_key_id": "", "private_payload_version": next, "updated_at": s.task5Now()})
	if q.Error != nil {
		return ErrParticipantFailure
	}
	if q.RowsAffected != 1 {
		return ErrParticipantConflict
	}
	return nil
}

func (s *GORMStore) privacyRejectFencedEffects(ctx context.Context, tx *gorm.DB, effects []NewEffect) error {
	for _, effect := range effects {
		var row subjectFenceRow
		if len(effect.SubjectKey) != 0 && len(effect.SubjectKey) != sha256.Size {
			return ErrInvalidMetadata
		}
		if len(effect.SubjectKey) == 0 {
			var count int64
			if err := tx.Model(&subjectFenceRow{}).Where("scope = ?", privacyFenceScope).Count(&count).Error; err != nil {
				return ErrParticipantFailure
			}
			if count > 0 {
				return ErrInvalidTransition
			}
			continue
		}
		err := tx.Where("subject_key = ? AND scope = ?", effect.SubjectKey, privacyFenceScope).First(&row).Error
		if err == nil {
			return ErrInvalidTransition
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
	}
	return nil
}

func (s *GORMStore) PrivacyFinalizeOperation(ctx context.Context, operationID string, expected uint64, status string) (uint64, error) {
	next, lookupErr := nextVersion(expected)
	if lookupErr != nil {
		return 0, lookupErr
	}
	var row operationRow
	if err := s.db.GORM().WithContext(ctx).Where("operation_id = ? AND version = ?", operationID, expected).First(&row).Error; err != nil {
		return 0, ErrParticipantConflict
	}
	plain, lookupErr := a6Open(ctx, s.keySource, "operation-private/v1", operationID, row.PrincipalID, row.Version, row.PrivateKeyID, row.PrivateContext, row.PrivateNonce)
	if lookupErr != nil {
		return 0, lookupErr
	}
	private, lookupErr := unmarshalPrivacyContext(plain)
	if lookupErr != nil {
		return 0, lookupErr
	}
	fenceKey, lookupErr := privacySubjectKey(ctx, s, private.GroupID)
	if lookupErr != nil {
		return 0, lookupErr
	}
	opDigest := sha256.Sum256([]byte(operationID))
	scopesDigest := sha256.Sum256([]byte(strings.Join(private.Scopes, ",")))
	requestDigest := append([]byte(nil), private.ConfirmationDigest...)
	audit := privacyAuditRow{AuditID: hexBytes(opDigest[:]), OperationDigest: opDigest[:], ScopesDigest: scopesDigest[:], RequestDigest: requestDigest, GroupRecord: private.Counts.GroupRecord, Players: private.Counts.Players, Attrs: private.Counts.Attrs, LogSessions: private.Counts.LogSessions, LogStates: private.Counts.LogStates, LogEntries: private.Counts.LogEntries, LogIntents: private.Counts.LogIntents, LogImports: private.Counts.LogImports, Status: status, CreatedAt: s.task5Now()}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return 0, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return 0, err
	}
	var unresolved, unresolvedOutbox int64
	if err := tx.Model(&inboxMessageRow{}).Where("(subject_key = ? OR subject_key IS NULL OR length(subject_key) <> 32) AND status IN ?", fenceKey, []string{InboxStatusCallbackStarted, InboxStatusAmbiguous}).Count(&unresolved).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	if err := tx.Model(&outboxEffectRow{}).Where("(subject_key = ? OR subject_key IS NULL OR length(subject_key) <> 32) AND status IN ?", fenceKey, []string{OutboxStatusPending, OutboxStatusLeased, OutboxStatusAmbiguous, OutboxStatusDispatched}).Count(&unresolvedOutbox).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	if unresolved+unresolvedOutbox > 0 {
		return 0, ErrInvalidTransition
	}
	var fence subjectFenceRow
	if err := tx.Where("subject_key = ? AND scope = ?", fenceKey, privacyFenceScope).First(&fence).Error; err != nil {
		return 0, ErrParticipantConflict
	}
	if fence.PurgeOperationID != operationID {
		return 0, ErrAuthenticationFailed
	}
	if err := tx.Exec(`CREATE TABLE IF NOT EXISTS privacy_purge_audit (audit_id VARCHAR(64) PRIMARY KEY, operation_digest BLOB NOT NULL, scopes_digest BLOB NOT NULL, request_digest BLOB NOT NULL, group_record INTEGER NOT NULL, players INTEGER NOT NULL, attrs INTEGER NOT NULL, log_sessions INTEGER NOT NULL DEFAULT 0, log_states INTEGER NOT NULL DEFAULT 0, log_entries INTEGER NOT NULL DEFAULT 0, log_intents INTEGER NOT NULL DEFAULT 0, log_imports INTEGER NOT NULL DEFAULT 0, status VARCHAR(32) NOT NULL, created_at DATETIME NOT NULL)`).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	if err := tx.Create(&audit).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	if err := tx.Where("subject_key = ? AND scope = ? AND version = ? AND purge_operation_id = ?", fenceKey, privacyFenceScope, fence.Version, operationID).Delete(&subjectFenceRow{}).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	q := tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?", operationID, expected).Updates(map[string]any{"version": next, "status": status, "private_context": nil, "private_nonce": nil, "private_key_id": "", "private_payload_version": next, "updated_at": s.task5Now()})
	if q.Error != nil {
		return 0, ErrParticipantFailure
	}
	if q.RowsAffected != 1 {
		return 0, ErrParticipantConflict
	}
	if err := tx.Commit().Error; err != nil {
		return 0, ErrParticipantFailure
	}
	return next, nil
}

var _ = time.Time{}
