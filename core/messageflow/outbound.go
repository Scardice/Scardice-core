package messageflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"sync"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

var (
	ErrEndpointUnavailable = errors.New("messageflow: endpoint unavailable")
	ErrCapabilityDenied = errors.New("messageflow: capability denied")
	ErrCommandConflict = errors.New("messageflow: command conflicts with existing request")
	ErrMissingOperationLookup = errors.New("messageflow: durable operation lookup unavailable")
)

type EndpointSnapshot struct {
	EndpointID adapterapi.EndpointID
	DesiredState string
	ObservedState adapterapi.ObservedState
	Capabilities adapterapi.CapabilitySet
	Actions adapterapi.ActionSet
	IndexRoot []byte
	IndexRootID string
}

type EndpointResolver interface { Resolve(context.Context, adapterapi.EndpointID) (EndpointSnapshot,error) }
type OperationLookup interface { GetOperationByIdempotency(context.Context,string,string,string) (eventstore.OperationView,error) }
type IDGenerator interface { NewID() (string,error) }
type BoundEncryptor interface { EncryptBound(context.Context,string,string,string,uint64,[]byte)([]byte,[]byte,string,error) }

type SubmitRequest struct {
	Effect adapterapi.OutboundEffect
	CommandID string
	PrincipalID adapterapi.PrincipalID
	CorrelationID adapterapi.CorrelationID
	CausationID adapterapi.CausationID
}
type SubmitResult struct { OperationID string; EffectID string; Digest []byte; Deduplicated bool }


type effectWire struct { Effect adapterapi.OutboundEffect `json:"effect"`; RawTarget string `json:"rawTarget,omitempty"` }
type effectDigestProjection struct {
	Version              adapterapi.EffectVersion     `json:"version,omitempty"`
	EndpointID           adapterapi.EndpointID        `json:"endpointId,omitempty"`
	Risk                 adapterapi.EffectRisk        `json:"risk,omitempty"`
	RetryClass           adapterapi.EffectRetryClass  `json:"retryClass,omitempty"`
	RequiredCapabilities adapterapi.CapabilitySet     `json:"requiredCapabilities,omitempty"`
	RequiredAction       adapterapi.ActionKind        `json:"requiredAction,omitempty"`
	Kind                 adapterapi.EffectKind        `json:"kind"`
	Action               adapterapi.ActionKind        `json:"action,omitempty"`
	Payload              adapterapi.EffectPayload     `json:"payload,omitempty"`
}

func logicalDigestBytes(e adapterapi.OutboundEffect) ([]byte, error) {
	projection := effectDigestProjection{
		Version:              e.Version,
		EndpointID:           e.EndpointID,
		Risk:                 e.Risk,
		RetryClass:           e.RetryClass,
		RequiredCapabilities: e.RequiredCapabilities,
		RequiredAction:       e.RequiredAction,
		Kind:                 e.Kind,
		Action:               e.Action,
		Payload:              e.Payload,
	}
	raw := ""
	if e.Payload.Target.Kind == adapterapi.TargetRaw {
		raw = e.Payload.Target.Raw
	}
	return json.Marshal(struct {
		Effect   effectDigestProjection `json:"effect"`
		RawTarget string                 `json:"rawTarget,omitempty"`
	}{Effect: projection, RawTarget: raw})
}

func effectBytes(e adapterapi.OutboundEffect) ([]byte,error) {
	raw:=""; if e.Payload.Target.Kind==adapterapi.TargetRaw { raw=e.Payload.Target.Raw }
	return json.Marshal(effectWire{Effect:e,RawTarget:raw})
}
func keyedDigest(root, payload []byte) []byte { m:=hmac.New(sha256.New,root); m.Write([]byte("outbound-request/v1")); m.Write(payload); return m.Sum(nil) }
func laneMAC(e adapterapi.OutboundEffect) ([]byte,error) { if e.Lane.MAC=="" { return nil,errors.New("messageflow: missing lane mac") }; b,err:=hex.DecodeString(e.Lane.MAC);if err!=nil{return nil,errors.New("messageflow: invalid lane mac")};return b,nil }
func privacySubjectKey(root []byte, subject string) []byte {
	m := hmac.New(sha256.New, root)
	m.Write([]byte("privacy-subject/v1"))
	m.Write([]byte(subject))
	return m.Sum(nil)
}
func riskClass(r adapterapi.EffectRisk, retry adapterapi.EffectRetryClass) string {
	switch retry { case adapterapi.EffectRetryPreDispatch: return eventstore.RiskPreDispatchRetryable; case adapterapi.EffectRetryNonIdempotent: return eventstore.RiskNonIdempotentAfterDispatch; default: return eventstore.RiskProviderIdempotent }
}
func effectType(k adapterapi.EffectKind) string { if k==adapterapi.EffectKindMessage{return "message"}; return "action" }
type OutboundOption func(*OutboundService)
type OutboundService struct { store eventstore.Store; resolver EndpointResolver; encryptor BoundEncryptor; ids IDGenerator; clock eventstore.Clock; serial sync.Mutex }
func NewOutboundService(store eventstore.Store, resolver EndpointResolver, encryptor BoundEncryptor, ids IDGenerator, options ...OutboundOption) (*OutboundService,error) {
	if store==nil || resolver==nil || encryptor==nil || ids==nil{return nil,errors.New("messageflow: dependencies required")}
	if _,ok:=store.(OperationLookup); !ok{return nil,ErrMissingOperationLookup}
	s:=&OutboundService{store:store,resolver:resolver,encryptor:encryptor,ids:ids,clock:eventstore.SystemClock{}}
	for _,option:=range options { if option!=nil {option(s)} }; return s,nil
}
func (s *OutboundService) Submit(ctx context.Context, req SubmitRequest) (SubmitResult,error) {
	s.serial.Lock(); defer s.serial.Unlock()
	e:=req.Effect
	if !req.PrincipalID.Valid(){return SubmitResult{},adapterapi.ErrInvalidContract}
	if req.CommandID=="" {return SubmitResult{},errors.New("messageflow: command id required")}
	if req.CorrelationID!="" {e.CorrelationID=req.CorrelationID}; if req.CausationID!="" {e.CausationID=req.CausationID}
	if e.CorrelationID=="" || !e.CorrelationID.Valid() || (e.CausationID!="" && !e.CausationID.Valid()) { return SubmitResult{},adapterapi.ErrInvalidContract }
	if e.ID=="" {id,allocErr:=s.ids.NewID();if allocErr!=nil{return SubmitResult{},allocErr};e.ID=adapterapi.EffectID(id)}
	if e.OperationID=="" {id,allocErr:=s.ids.NewID();if allocErr!=nil{return SubmitResult{},allocErr};e.OperationID=adapterapi.OperationID(id)}
	if e.Version!=adapterapi.EffectVersionOne || e.EndpointID=="" {return SubmitResult{},adapterapi.ErrInvalidContract}
	if err:=e.Validate();err!=nil{return SubmitResult{},err}
	snap,err:=s.resolver.Resolve(ctx,e.EndpointID);if err!=nil{return SubmitResult{},ErrEndpointUnavailable}
	if snap.EndpointID!=e.EndpointID { return SubmitResult{},ErrEndpointUnavailable }
	if len(snap.IndexRoot)!=32 || snap.IndexRootID=="" { return SubmitResult{},ErrEndpointUnavailable }
	if err:=e.Lane.Verify(snap.IndexRoot,e.EndpointID,e.Payload.Target); err!=nil{return SubmitResult{},ErrEndpointUnavailable}
	plain,err:=effectBytes(e);if err!=nil{return SubmitResult{},err}
	digestPlain,err:=logicalDigestBytes(e);if err!=nil{return SubmitResult{},err}; digest:=keyedDigest(snap.IndexRoot,digestPlain)
	lookup:=s.store.(OperationLookup)
	if view,lookupErr:=lookup.GetOperationByIdempotency(ctx,string(req.PrincipalID),"outbound",req.CommandID); lookupErr==nil {
		if !hmac.Equal(view.RequestDigest,digest) { return SubmitResult{},ErrCommandConflict }
		return SubmitResult{OperationID:view.OperationID,EffectID:view.ResourceID,Digest:append([]byte(nil),digest...),Deduplicated:true},nil
	} else if !errors.Is(lookupErr,eventstore.ErrNotFound) { return SubmitResult{},lookupErr }
	now:=s.clock.Now().UTC()
	if snap.DesiredState!="enabled" || snap.ObservedState!=adapterapi.ObservedStateConnected { return SubmitResult{},ErrEndpointUnavailable }
	if !e.Deadline.After(now) { return SubmitResult{},ErrEndpointUnavailable }
	if err:=e.ValidateForCapabilities(snap.Capabilities,snap.Actions);err!=nil{return SubmitResult{},ErrCapabilityDenied}
	effectID:=e.ID
	opID:=e.OperationID
	cipher,nonce,keyID,err:=s.encryptor.EncryptBound(ctx,"outbox/v1",string(effectID),string(e.EndpointID),1,plain);if err!=nil{return SubmitResult{},err}
	lane,err:=laneMAC(e);if err!=nil{return SubmitResult{},err}
	expiry:=time.Time{}; if e.Deadline.After(now) && !e.Deadline.After(now.Add(eventstore.InboxPayloadTTL)) { expiry=e.Deadline }
	eventID,allocErr:=s.ids.NewID(); if allocErr!=nil{return SubmitResult{},allocErr}; effectEventID:=eventID
	segmentKinds:=make([]string,0,len(e.Payload.Segments)); for _,segment:=range e.Payload.Segments { segmentKinds=append(segmentKinds,segment.Kind) }
	eventPayload,marshalErr:=json.Marshal(struct{Version uint64 `json:"version"`;EffectID string `json:"effectId"`;OperationID string `json:"operationId"`;EndpointID string `json:"endpointId"`;RequestDigest string `json:"requestDigest"`;DigestKeyID string `json:"digestKeyId"`;PayloadKind adapterapi.EffectPayloadKind `json:"payloadKind"`;SegmentKinds []string `json:"segmentKinds,omitempty"`;SegmentCount int `json:"segmentCount"`;TargetDigest string `json:"targetDigest"`;LaneKey string `json:"laneKey"`;LaneMAC string `json:"laneMac"`;Risk adapterapi.EffectRisk `json:"risk"`}{1,string(effectID),string(opID),string(e.EndpointID),hex.EncodeToString(digest),snap.IndexRootID,e.Payload.Kind,segmentKinds,len(e.Payload.Segments),e.Lane.TargetDigest,e.Lane.Key,e.Lane.MAC,e.Risk}); if marshalErr!=nil{return SubmitResult{},errors.New("messageflow: shape event encoding failed")}
	work:=eventstore.UnitOfWork{Streams:[]eventstore.StreamAppend{{Stream:eventstore.StreamID{AggregateType:"outbound-effect",AggregateID:string(effectID)},Events:[]eventstore.NewEvent{{EventType:"OutboundEffectRequestedV1",SchemaVersion:1,Payload:eventPayload,Metadata:eventstore.Metadata{EventID:effectEventID,CommandID:req.CommandID,CorrelationID:string(e.CorrelationID),CausationID:string(e.CausationID),PrincipalID:string(req.PrincipalID),Producer:"core/messageflow",OccurredAt:now}}}}},Operations:[]eventstore.OperationUpdate{{OperationID:string(opID),Kind:"outbound-effect",Status:"pending",PrincipalID:string(req.PrincipalID),ResourceID:string(effectID),RequestID:req.CommandID,CorrelationID:string(e.CorrelationID),IdempotencyScope:"outbound",IdempotencyKey:req.CommandID,RequestDigest:digest,CreatedAt:now,UpdatedAt:now}},Effects:[]eventstore.NewEffect{{EffectID:string(effectID),EndpointID:string(e.EndpointID),LaneHMAC:lane,EffectType:effectType(e.Kind),RiskClass:riskClass(e.Risk,e.RetryClass),Status:eventstore.OutboxStatusPending,DeadlineAt:e.Deadline,PayloadCiphertext:cipher,PayloadNonce:nonce,ContentDigest:digest,DigestKeyID:"",PayloadEncryptionKeyID:keyID,ContentDigestKeyID:snap.IndexRootID,PayloadExpiresAt:expiry}}}
	subject := string(e.Payload.Target.Conversation)
	if subject == "" { subject = string(e.Payload.Target.Member) }
	subjectKey := privacySubjectKey(snap.IndexRoot, subject)
	work.Streams[0].Events[0].Metadata.SubjectKey = subjectKey
	work.Effects[0].SubjectKey = subjectKey
	result,err:=s.store.Commit(ctx,work)
	if err!=nil {
		if view,lookupErr:=s.store.(OperationLookup).GetOperationByIdempotency(ctx,string(req.PrincipalID),"outbound",req.CommandID); lookupErr==nil {
			if !hmac.Equal(view.RequestDigest,digest){return SubmitResult{},ErrCommandConflict}
			return SubmitResult{OperationID:view.OperationID,EffectID:view.ResourceID,Digest:append([]byte(nil),digest...),Deduplicated:true},nil
		}
		return SubmitResult{},err
	}
	accepted:=SubmitResult{OperationID:string(opID),EffectID:string(effectID),Digest:digest,Deduplicated:result.Deduplicated}; return accepted,nil
}

