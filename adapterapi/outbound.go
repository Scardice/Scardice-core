package adapterapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type EffectVersion uint16

const EffectVersionOne EffectVersion = 1

type EffectRisk uint8

const (
	EffectRiskInvalid EffectRisk = iota
	EffectRiskNormal
	EffectRiskHigh
)

func (risk EffectRisk) Valid() bool { return risk == EffectRiskNormal || risk == EffectRiskHigh }

type EffectRetryClass uint8

const (
	EffectRetryInvalid EffectRetryClass = iota
	EffectRetryPreDispatch
	EffectRetryProviderIdempotent
	EffectRetryNonIdempotent
)

func (retry EffectRetryClass) Valid() bool {
	switch retry {
	case EffectRetryPreDispatch, EffectRetryProviderIdempotent, EffectRetryNonIdempotent:
		return true
	}
	return false
}

type TargetKind uint8

const (
	TargetInvalid TargetKind = iota
	TargetPerson
	TargetGroup
	TargetRaw
)

func (kind TargetKind) Valid() bool {
	switch kind {
	case TargetPerson, TargetGroup, TargetRaw:
		return true
	}
	return false
}

type EffectTarget struct {
	Kind         TargetKind     `json:"kind"`
	Conversation ConversationID `json:"conversation,omitempty"`
	Member       PrincipalID    `json:"member,omitempty"`
	Raw          string         `json:"-"`
}

func (target EffectTarget) ProviderRawTarget() string { return target.Raw }

func safeArtifactFilename(filename string) bool {
	return filename == "" || (filename != "." && filename != ".." && len(filename) <= MaxEffectFieldBytes && !strings.ContainsAny(filename, `/\\:`) && validOptionalIdentifier(filename))
}
func (input ArtifactInput) Validate() error {
	if !input.ID.Valid() || len(input.ContentType) > MaxEffectFieldBytes || !safeArtifactFilename(input.Filename) {
		return fmt.Errorf("%w: invalid artifact input", ErrInvalidContract)
	}
	return nil
}

type EffectPayloadKind uint8

const (
	EffectPayloadInvalid EffectPayloadKind = iota
	EffectPayloadPersonText
	EffectPayloadGroupText
	EffectPayloadSegments
	EffectPayloadFile
	EffectPayloadEdit
	EffectPayloadRecall
	EffectPayloadSetGroupCard
	EffectPayloadQuit
	EffectPayloadBan
	EffectPayloadKick
	EffectPayloadGroupInfoRefresh
)

func (kind EffectPayloadKind) Valid() bool {
	switch kind {
	case EffectPayloadPersonText, EffectPayloadGroupText, EffectPayloadSegments, EffectPayloadFile, EffectPayloadEdit, EffectPayloadRecall, EffectPayloadSetGroupCard, EffectPayloadQuit, EffectPayloadBan, EffectPayloadKick, EffectPayloadGroupInfoRefresh:
		return true
	}
	return false
}

func (target EffectTarget) Validate() error {
	if !target.Kind.Valid() {
		return fmt.Errorf("%w: invalid target kind", ErrInvalidContract)
	}
	if target.Kind == TargetRaw {
		if target.Conversation != "" || target.Member != "" || len(target.Raw) == 0 || len(target.Raw) > MaxEffectFieldBytes || !validOptionalIdentifier(target.Raw) {
			return fmt.Errorf("%w: invalid raw target", ErrInvalidContract)
		}
		return nil
	}
	if target.Raw != "" || !target.Conversation.Valid() || (target.Member != "" && !target.Member.Valid()) {
		return fmt.Errorf("%w: invalid normalized target", ErrInvalidContract)
	}
	return nil
}

const (
	SegmentKindText    = "text"
	SegmentKindImage   = "image"
	SegmentKindFile    = "file"
	SegmentKindMention = "mention"
)

type MessageSegment struct {
	Kind     string         `json:"kind"`
	Text     string         `json:"text,omitempty"`
	Artifact *ArtifactInput `json:"artifact,omitempty"`
}

func (segment MessageSegment) Validate() error {
	if len(segment.Text) > MaxEffectTextBytes {
		return fmt.Errorf("%w: invalid message segment", ErrInvalidContract)
	}
	switch segment.Kind {
	case SegmentKindText, SegmentKindMention:
		if segment.Text == "" || segment.Artifact != nil {
			return fmt.Errorf("%w: invalid text segment", ErrInvalidContract)
		}
	case SegmentKindImage, SegmentKindFile:
		if segment.Artifact == nil || segment.Text != "" {
			return fmt.Errorf("%w: invalid artifact segment", ErrInvalidContract)
		}
		if err := segment.Artifact.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown message segment kind", ErrInvalidContract)
	}
	return nil
}

type EffectPayload struct {
	Kind            EffectPayloadKind `json:"kind"`
	Target          EffectTarget      `json:"target"`
	Text            string            `json:"text,omitempty"`
	Segments        []MessageSegment  `json:"segments,omitempty"`
	File            ArtifactInput     `json:"file,omitempty"`
	MessageID       MessageID         `json:"messageId,omitempty"`
	Card            string            `json:"card,omitempty"`
	DurationSeconds uint32            `json:"durationSeconds,omitempty"`
	Reason          string            `json:"reason,omitempty"`
}

func (payload EffectPayload) Validate() error {
	if !payload.Kind.Valid() {
		return fmt.Errorf("%w: invalid effect payload", ErrInvalidContract)
	}
	if err := payload.Target.Validate(); err != nil {
		return err
	}
	if len(payload.Text) > MaxEffectTextBytes || len(payload.Card) > MaxEffectFieldBytes || len(payload.Reason) > MaxEffectFieldBytes || len(payload.Segments) > MaxEffectParameters {
		return fmt.Errorf("%w: effect payload exceeds bounds", ErrInvalidContract)
	}
	for _, segment := range payload.Segments {
		if err := segment.Validate(); err != nil {
			return err
		}
	}
	normalizedTarget := payload.Target.Kind == TargetPerson || payload.Target.Kind == TargetGroup
	noMember := payload.Target.Member == ""
	zeroFile := payload.File.ID == "" && payload.File.Filename == "" && payload.File.ContentType == ""
	zeroMessage := payload.MessageID == ""
	switch payload.Kind {
	case EffectPayloadPersonText:
		if payload.Target.Kind != TargetPerson || !noMember || !normalizedTarget || payload.Text == "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid person text payload", ErrInvalidContract)
		}
	case EffectPayloadGroupText:
		if payload.Target.Kind != TargetGroup || !noMember || payload.Text == "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid group text payload", ErrInvalidContract)
		}
	case EffectPayloadSegments:
		if !normalizedTarget || !noMember || len(payload.Segments) == 0 || payload.Text != "" || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid segments payload", ErrInvalidContract)
		}
	case EffectPayloadFile:
		if !normalizedTarget || !noMember || zeroFile || payload.Text != "" || len(payload.Segments) != 0 || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid file payload", ErrInvalidContract)
		}
		if err := payload.File.Validate(); err != nil {
			return err
		}
	case EffectPayloadEdit:
		if !normalizedTarget || !noMember || !zeroFile || zeroMessage || !payload.MessageID.Valid() || payload.Text == "" || len(payload.Segments) != 0 || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid edit payload", ErrInvalidContract)
		}
	case EffectPayloadRecall:
		if !normalizedTarget || !noMember || !zeroFile || zeroMessage || !payload.MessageID.Valid() || payload.Text != "" || len(payload.Segments) != 0 || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid recall payload", ErrInvalidContract)
		}
	case EffectPayloadSetGroupCard:
		if payload.Target.Kind != TargetGroup || !payload.Target.Member.Valid() || payload.Card == "" || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid group card payload", ErrInvalidContract)
		}
	case EffectPayloadQuit, EffectPayloadGroupInfoRefresh:
		if payload.Target.Kind != TargetGroup || !noMember || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid group action payload", ErrInvalidContract)
		}
	case EffectPayloadBan:
		if payload.Target.Kind != TargetGroup || !payload.Target.Member.Valid() || payload.DurationSeconds == 0 || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" {
			return fmt.Errorf("%w: invalid ban payload", ErrInvalidContract)
		}
	case EffectPayloadKick:
		if payload.Target.Kind != TargetGroup || !payload.Target.Member.Valid() || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 {
			return fmt.Errorf("%w: invalid kick payload", ErrInvalidContract)
		}
	}
	return nil
}
func payloadContract(kind EffectPayloadKind) (EffectKind, CapabilitySet, ActionKind, EffectRetryClass, EffectRisk, bool) {
	switch kind {
	case EffectPayloadPersonText, EffectPayloadGroupText:
		return EffectKindMessage, CapabilityOutbound, ActionKindSendMessage, EffectRetryNonIdempotent, EffectRiskNormal, true
	case EffectPayloadSegments:
		return EffectKindMessage, CapabilityOutbound | CapabilityRichMessages, ActionKindSendMessage, EffectRetryNonIdempotent, EffectRiskNormal, true
	case EffectPayloadFile:
		return EffectKindMessage, CapabilityOutbound | CapabilityArtifacts, ActionKindSendFile, EffectRetryNonIdempotent, EffectRiskNormal, true
	case EffectPayloadEdit:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindEditMessage, EffectRetryProviderIdempotent, EffectRiskNormal, true
	case EffectPayloadRecall:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindRecallMessage, EffectRetryProviderIdempotent, EffectRiskNormal, true
	case EffectPayloadSetGroupCard:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindSetGroupCard, EffectRetryNonIdempotent, EffectRiskHigh, true
	case EffectPayloadQuit:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindQuit, EffectRetryNonIdempotent, EffectRiskHigh, true
	case EffectPayloadBan:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindBan, EffectRetryNonIdempotent, EffectRiskHigh, true
	case EffectPayloadKick:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindKick, EffectRetryNonIdempotent, EffectRiskHigh, true
	case EffectPayloadGroupInfoRefresh:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindGroupInfoRefresh, EffectRetryProviderIdempotent, EffectRiskNormal, true
	}
	return 0, 0, 0, 0, 0, false
}
func canonicalTarget(target EffectTarget) []byte {
	var buf bytes.Buffer
	_ = buf.WriteByte(byte(target.Kind))
	for _, value := range []string{string(target.Conversation), string(target.Member), target.Raw} {
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(value)))
		_, _ = buf.WriteString(value)
	}
	return buf.Bytes()
}

type LaneMetadata struct {
	EndpointID   EndpointID `json:"endpointId"`
	TargetDigest string     `json:"targetDigest"`
	Key          string     `json:"key"`
	Sequence     uint64     `json:"sequence"`
	MAC          string     `json:"mac"`
}

// LaneSigner performs a domain-separated MAC without exposing the index-root
// material to the caller. The payload is the exact byte sequence covered by
// the returned MAC.
type LaneSigner func(label string, payload []byte) ([]byte, error)

func appendLaneLength(dst, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func NewLaneMetadataWithSigner(endpoint EndpointID, target EffectTarget, sequence uint64, signer LaneSigner) (LaneMetadata, error) {
	if !endpoint.Valid() || sequence == 0 || signer == nil {
		return LaneMetadata{}, fmt.Errorf("%w: invalid lane inputs", ErrInvalidContract)
	}
	if err := target.Validate(); err != nil {
		return LaneMetadata{}, err
	}
	targetInput := appendLaneLength(nil, []byte(endpoint))
	targetInput = append(targetInput, canonicalTarget(target)...)
	targetDigest, err := signer("target/v1\x00", targetInput)
	if err != nil || len(targetDigest) == 0 {
		return LaneMetadata{}, fmt.Errorf("%w: lane target signing failed", ErrInvalidContract)
	}
	targetDigestHex := hex.EncodeToString(targetDigest)
	laneInput := make([]byte, 0, 1+4+len(endpoint)+4+len(targetDigestHex))
	laneInput = append(laneInput, 1)
	laneInput = appendLaneLength(laneInput, []byte(endpoint))
	laneInput = appendLaneLength(laneInput, []byte(targetDigestHex))
	keyDigest, err := signer("lane/v1\x00", laneInput)
	if err != nil || len(keyDigest) == 0 {
		return LaneMetadata{}, fmt.Errorf("%w: lane key signing failed", ErrInvalidContract)
	}
	key := hex.EncodeToString(keyDigest)
	authInput := append(append([]byte(nil), laneInput...), []byte(key)...)
	authDigest, err := signer("lane-metadata/v1\x00", authInput)
	if err != nil || len(authDigest) == 0 {
		return LaneMetadata{}, fmt.Errorf("%w: lane authentication signing failed", ErrInvalidContract)
	}
	return LaneMetadata{
		EndpointID:   endpoint,
		TargetDigest: targetDigestHex,
		Key:          key,
		Sequence:     sequence,
		MAC:          hex.EncodeToString(authDigest),
	}, nil
}

func NewLaneMetadata(endpoint EndpointID, target EffectTarget, indexRoot []byte, sequence uint64) (LaneMetadata, error) {
	if len(indexRoot) == 0 {
		return LaneMetadata{}, fmt.Errorf("%w: invalid lane inputs", ErrInvalidContract)
	}
	return NewLaneMetadataWithSigner(endpoint, target, sequence, func(label string, payload []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, indexRoot)
		_, _ = mac.Write([]byte(label))
		_, _ = mac.Write(payload)
		return mac.Sum(nil), nil
	})
}

func (lane LaneMetadata) Validate() error {
	if !lane.EndpointID.Valid() || len(lane.TargetDigest) != 64 || len(lane.Key) != 64 || lane.Sequence == 0 || len(lane.MAC) != 64 {
		return fmt.Errorf("%w: invalid lane metadata", ErrInvalidContract)
	}
	for _, value := range []string{lane.TargetDigest, lane.Key, lane.MAC} {
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("%w: invalid lane digest", ErrInvalidContract)
		}
	}
	return nil
}

func (lane LaneMetadata) VerifyWithSigner(signer LaneSigner, endpoint EndpointID, target EffectTarget) error {
	expected, err := NewLaneMetadataWithSigner(endpoint, target, lane.Sequence, signer)
	if err != nil {
		return err
	}
	if expected.EndpointID != lane.EndpointID || expected.TargetDigest != lane.TargetDigest || expected.Key != lane.Key || expected.MAC != lane.MAC {
		return fmt.Errorf("%w: lane authentication mismatch", ErrInvalidContract)
	}
	return nil
}

func (lane LaneMetadata) Verify(indexRoot []byte, endpoint EndpointID, target EffectTarget) error {
	if len(indexRoot) == 0 {
		return fmt.Errorf("%w: invalid lane inputs", ErrInvalidContract)
	}
	return lane.VerifyWithSigner(func(label string, payload []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, indexRoot)
		_, _ = mac.Write([]byte(label))
		_, _ = mac.Write(payload)
		return mac.Sum(nil), nil
	}, endpoint, target)
}

type ImmutableArtifactMetadata struct {
	ID          ArtifactID `json:"id,omitempty"`
	ContentType string     `json:"contentType,omitempty"`
	Filename    string     `json:"filename,omitempty"`
}

func (artifact ArtifactResult) ImmutableMetadata() ImmutableArtifactMetadata {
	return ImmutableArtifactMetadata{ID: artifact.ID, ContentType: artifact.ContentType, Filename: artifact.Filename}
}
