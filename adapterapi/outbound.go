package adapterapi

import (
	"encoding/json"
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
	case EffectRetryInvalid:
		return false
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
	case TargetInvalid:
		return false
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
	EffectPayloadAnswerRequest
	EffectPayloadAdapterAPI
	EffectPayloadForward
)

func (kind EffectPayloadKind) Valid() bool {
	switch kind {
	case EffectPayloadInvalid:
		return false
	case EffectPayloadPersonText, EffectPayloadGroupText, EffectPayloadSegments, EffectPayloadFile, EffectPayloadEdit, EffectPayloadRecall, EffectPayloadSetGroupCard, EffectPayloadQuit, EffectPayloadBan, EffectPayloadKick, EffectPayloadGroupInfoRefresh, EffectPayloadAnswerRequest, EffectPayloadAdapterAPI, EffectPayloadForward:
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

type ForwardMessageNode struct {
	SenderID   PrincipalID `json:"senderId"`
	SenderName string      `json:"senderName"`
	Content    string      `json:"content"`
}

func (node ForwardMessageNode) Validate() error {
	if !node.SenderID.Valid() || len(node.SenderName) > MaxEffectFieldBytes ||
		len(node.Content) > MaxEffectTextBytes || strings.TrimSpace(node.Content) == "" {
		return fmt.Errorf("%w: invalid forward message node", ErrInvalidContract)
	}
	return nil
}

type EffectPayload struct {
	Kind            EffectPayloadKind    `json:"kind"`
	Target          EffectTarget         `json:"target"`
	Text            string               `json:"text,omitempty"`
	Segments        []MessageSegment     `json:"segments,omitempty"`
	ForwardNodes    []ForwardMessageNode `json:"forwardNodes,omitempty"`
	File            ArtifactInput        `json:"file,omitempty"`
	MessageID       MessageID            `json:"messageId,omitempty"`
	Card            string               `json:"card,omitempty"`
	DurationSeconds uint32               `json:"durationSeconds,omitempty"`
	Reason          string               `json:"reason,omitempty"`
	// RequestID and Approve answer a provider request (a friend request when the
	// target is a person, a group invitation when it is a group). Reason is the
	// optional rejection explanation.
	RequestID string `json:"requestId,omitempty"`
	Approve   bool   `json:"approve,omitempty"`
	// RequestJSON is an exact, complete provider request envelope. Validation
	// bounds it to a JSON object but intentionally does not interpret actions.
	RequestJSON string `json:"requestJson,omitempty"`
}

func (payload EffectPayload) Validate() error {
	if !payload.Kind.Valid() {
		return fmt.Errorf("%w: invalid effect payload", ErrInvalidContract)
	}
	if err := payload.Target.Validate(); err != nil {
		return err
	}
	if len(payload.Text) > MaxEffectTextBytes || len(payload.Card) > MaxEffectFieldBytes || len(payload.Reason) > MaxEffectFieldBytes || len(payload.Segments) > MaxEffectParameters || len(payload.ForwardNodes) > MaxEffectParameters {
		return fmt.Errorf("%w: effect payload exceeds bounds", ErrInvalidContract)
	}
	for _, segment := range payload.Segments {
		if err := segment.Validate(); err != nil {
			return err
		}
	}
	for _, node := range payload.ForwardNodes {
		if err := node.Validate(); err != nil {
			return err
		}
	}
	if payload.Kind != EffectPayloadAnswerRequest && (payload.RequestID != "" || payload.Approve) {
		return fmt.Errorf("%w: request answer fields on a non-answer payload", ErrInvalidContract)
	}
	if payload.Kind != EffectPayloadAdapterAPI && payload.RequestJSON != "" {
		return fmt.Errorf("%w: adapter request JSON on a non-adapter payload", ErrInvalidContract)
	}
	if payload.Kind != EffectPayloadForward && len(payload.ForwardNodes) != 0 {
		return fmt.Errorf("%w: forward nodes on a non-forward payload", ErrInvalidContract)
	}
	normalizedTarget := payload.Target.Kind == TargetPerson || payload.Target.Kind == TargetGroup
	noMember := payload.Target.Member == ""
	zeroFile := payload.File.ID == "" && payload.File.Filename == "" && payload.File.ContentType == ""
	zeroMessage := payload.MessageID == ""
	switch payload.Kind {
	case EffectPayloadInvalid:
		return fmt.Errorf("%w: invalid effect payload", ErrInvalidContract)
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
	case EffectPayloadForward:
		if !normalizedTarget || !noMember || len(payload.ForwardNodes) == 0 || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" {
			return fmt.Errorf("%w: invalid forward payload", ErrInvalidContract)
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
		// An empty card clears the member's existing group card.
		if payload.Target.Kind != TargetGroup || !payload.Target.Member.Valid() || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.DurationSeconds != 0 || payload.Reason != "" {
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
	case EffectPayloadAnswerRequest:
		if !normalizedTarget || !noMember || payload.RequestID == "" || len(payload.RequestID) > MaxEffectFieldBytes || !validOptionalIdentifier(payload.RequestID) || payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage || payload.Card != "" || payload.DurationSeconds != 0 {
			return fmt.Errorf("%w: invalid request answer payload", ErrInvalidContract)
		}
	case EffectPayloadAdapterAPI:
		if payload.Target.Kind != TargetRaw || payload.Target.Raw != "adapter-api" ||
			payload.Text != "" || len(payload.Segments) != 0 || !zeroFile || !zeroMessage ||
			payload.Card != "" || payload.DurationSeconds != 0 || payload.Reason != "" ||
			payload.RequestID != "" || payload.Approve {
			return fmt.Errorf("%w: invalid adapter API payload", ErrInvalidContract)
		}
		if err := ValidateProtocolJSON(payload.RequestJSON); err != nil {
			return err
		}
	}
	return nil
}
func payloadContract(kind EffectPayloadKind) (EffectKind, CapabilitySet, ActionKind, EffectRetryClass, EffectRisk, bool) {
	switch kind {
	case EffectPayloadInvalid:
		return 0, 0, 0, 0, 0, false
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
	case EffectPayloadAnswerRequest:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindAnswerRequest, EffectRetryNonIdempotent, EffectRiskNormal, true
	case EffectPayloadForward:
		return EffectKindMessage, CapabilityOutbound | CapabilityRichMessages, ActionKindSendMessage, EffectRetryNonIdempotent, EffectRiskNormal, true
	case EffectPayloadAdapterAPI:
		return EffectKindAction, CapabilityOutbound | CapabilityActions, ActionKindAdapterAPI, EffectRetryNonIdempotent, EffectRiskNormal, true
	}
	return 0, 0, 0, 0, 0, false
}

// LaneMetadata identifies an endpoint's destination queue. Sequence is transport
// metadata; the store allocates the durable FIFO sequence when it accepts work.
type LaneMetadata struct {
	EndpointID EndpointID `json:"endpointId"`
	Key        string     `json:"key"`
	Sequence   uint64     `json:"sequence"`
}

func NewLaneMetadata(endpoint EndpointID, target EffectTarget, sequence uint64) (LaneMetadata, error) {
	if !endpoint.Valid() || sequence == 0 {
		return LaneMetadata{}, fmt.Errorf("%w: invalid lane inputs", ErrInvalidContract)
	}
	if err := target.Validate(); err != nil {
		return LaneMetadata{}, err
	}
	kind, destination := "person", string(target.Conversation)
	switch target.Kind {
	case TargetInvalid, TargetPerson:
	case TargetGroup:
		kind = "group"
	case TargetRaw:
		kind, destination = "raw", target.Raw
	}
	// Member-specific actions serialize with messages to their conversation.
	// JSON string framing keeps identifiers readable and unambiguous.
	key, err := json.Marshal([3]string{string(endpoint), kind, destination})
	if err != nil {
		return LaneMetadata{}, err
	}
	return LaneMetadata{EndpointID: endpoint, Key: string(key), Sequence: sequence}, nil
}

func (lane LaneMetadata) Validate() error {
	const maxLaneKeyBytes = 6*(MaxIdentifierBytes+MaxEffectFieldBytes) + 32
	if !lane.EndpointID.Valid() || lane.Sequence == 0 || len(lane.Key) == 0 || len(lane.Key) > maxLaneKeyBytes {
		return fmt.Errorf("%w: invalid lane metadata", ErrInvalidContract)
	}
	var identity [3]string
	if err := json.Unmarshal([]byte(lane.Key), &identity); err != nil || identity[0] != string(lane.EndpointID) {
		return fmt.Errorf("%w: invalid lane identity", ErrInvalidContract)
	}
	target := EffectTarget{Conversation: ConversationID(identity[2])}
	switch identity[1] {
	case "person":
		target.Kind = TargetPerson
	case "group":
		target.Kind = TargetGroup
	case "raw":
		target = EffectTarget{Kind: TargetRaw, Raw: identity[2]}
	default:
		return fmt.Errorf("%w: invalid lane target kind", ErrInvalidContract)
	}
	return lane.Verify(lane.EndpointID, target)
}

func (lane LaneMetadata) Verify(endpoint EndpointID, target EffectTarget) error {
	expected, err := NewLaneMetadata(endpoint, target, lane.Sequence)
	if err != nil {
		return err
	}
	if lane != expected {
		return fmt.Errorf("%w: lane identity mismatch", ErrInvalidContract)
	}
	return nil
}

type ImmutableArtifactMetadata struct {
	ID          ArtifactID `json:"id,omitempty"`
	ContentType string     `json:"contentType,omitempty"`
	Filename    string     `json:"filename,omitempty"`
}

func (artifact ArtifactResult) ImmutableMetadata() ImmutableArtifactMetadata {
	return ImmutableArtifactMetadata{ID: artifact.ID, ContentType: artifact.ContentType, Filename: artifact.Filename}
}
