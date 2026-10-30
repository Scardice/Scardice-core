package emitter

// fork from https://github.com/nsxdevx/nsxbot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"

	socketio "github.com/PaienNate/pineutil/evsocket/v2"

	"Scardice-core/adapterapi"
	"Scardice-core/dice/imsdk/onebot/schema"
	"Scardice-core/dice/imsdk/onebot/types"
)

// EchoTimeOut ws onebot await echo message time out
var EchoTimeOut = 10 * time.Second

// ErrInvalidRawRequest means validation failed before any provider I/O.
var ErrInvalidRawRequest = fmt.Errorf("%w: invalid OneBot raw request", adapterapi.ErrInvalidContract)

type Emitter interface {
	SendPvtMsg(ctx context.Context, userId int64, msg schema.MessageChain) (*types.SendMsgRes, error)
	SendGrMsg(ctx context.Context, groupId int64, msg schema.MessageChain) (*types.SendMsgRes, error)
	GetMsg(ctx context.Context, msgId int64) (*types.GetMsgRes, error)
	DelMsg(ctx context.Context, msgId int64) error
	GetLoginInfo(ctx context.Context) (*types.LoginInfo, error)
	GetStrangerInfo(ctx context.Context, userId int64, noCache bool) (*types.StrangerInfo, error)
	GetStatus(ctx context.Context) (*types.Status, error)
	GetVersionInfo(ctx context.Context) (*types.VersionInfo, error)
	GetSelfId(ctx context.Context) (int64, error)
	SetSelfId(ctx context.Context, selfId int64) error
	SetFriendAddRequest(ctx context.Context, flag string, approve bool, remark string) error
	SetGroupAddRequest(ctx context.Context, flag string, subType string, approve bool, reason string) error
	SetGroupSpecialTitle(ctx context.Context, groupId int64, userId int64, specialTitle string, duration int) error

	// 并非Onebot11大典的逻辑，是补充逻辑

	QuitGroup(ctx context.Context, groupId int64) error
	SetGroupCard(ctx context.Context, groupId int64, userId int64, card string) error
	GetGroupInfo(ctx context.Context, groupId int64, noCache bool) (*types.GroupInfo, error)
	GetGroupMemberInfo(ctx context.Context, groupId int64, userId int64, noCache bool) (*types.GroupMemberInfo, error)
	Raw(ctx context.Context, action Action, params any) ([]byte, error)
	RawJSON(ctx context.Context, request []byte) ([]byte, error)

	HandleEcho(echo string, raw []byte)
	Close()

	GetDroppedEchoCount() uint64
}

var _ Emitter = (*emitterSocket)(nil)

type Request[T any] struct {
	Echo   string `json:"echo"`
	Action Action `json:"action"`
	Params T      `json:"params,omitempty"`
}

type Response[T any] struct {
	Status  string `json:"status"`
	RetCode int    `json:"retcode"`
	Message string `json:"message,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Wording string `json:"wording,omitempty"`
	Data    T      `json:"data,omitempty"`
	Echo    string `json:"echo"`
}

func (r *Response[T]) UnmarshalJSON(data []byte) error {
	type rawResponse struct {
		Status       string                 `json:"status"`
		RetCode      int                    `json:"retcode"`
		RetCodeCamel int                    `json:"retCode"`
		Message      sonic.NoCopyRawMessage `json:"message"`
		Msg          sonic.NoCopyRawMessage `json:"msg"`
		Wording      sonic.NoCopyRawMessage `json:"wording"`
		Data         T                      `json:"data,omitempty"`
		Echo         string                 `json:"echo"`
	}

	var aux rawResponse
	if err := sonic.Unmarshal(data, &aux); err != nil {
		return err
	}

	r.Status = aux.Status
	r.RetCode = aux.RetCode
	if r.RetCode == 0 && aux.RetCodeCamel != 0 {
		r.RetCode = aux.RetCodeCamel
	}
	r.Message = responseDiagnosticString(aux.Message)
	r.Msg = responseDiagnosticString(aux.Msg)
	r.Wording = responseDiagnosticString(aux.Wording)
	r.Data = aux.Data
	r.Echo = aux.Echo
	return nil
}

func responseDiagnosticString(raw sonic.NoCopyRawMessage) string {
	// Legacy echo decoding also sees inbound events whose message is a segment array.
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var value string
	_ = sonic.Unmarshal(raw, &value)
	return value
}

type emitterSocket struct {
	mu     sync.Mutex
	conn   *socketio.WebsocketWrapper
	selfId int64
	closed bool
	done   chan struct{}

	waiters sync.Map // map[string]chan []byte

	droppedEchoCount uint64
}

func NewEVEmitter(conn *socketio.WebsocketWrapper) *emitterSocket {
	emitter := &emitterSocket{
		conn: conn,
		done: make(chan struct{}),
	}
	return emitter
}

func (e *emitterSocket) HandleEcho(echo string, raw []byte) {
	chAny, ok := e.waiters.Load(echo)
	if echo == "" || !ok {
		atomic.AddUint64(&e.droppedEchoCount, 1)
		return
	}
	ch := chAny.(chan []byte)
	// The waiter outlives the transport callback; retain our own frame bytes.
	select {
	case ch <- append([]byte(nil), raw...):
	default:
		atomic.AddUint64(&e.droppedEchoCount, 1)
	}
}

func (e *emitterSocket) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		if e.done != nil {
			close(e.done)
		}
	}
}

func (e *emitterSocket) GetDroppedEchoCount() uint64 {
	return atomic.LoadUint64(&e.droppedEchoCount)
}

func (e *emitterSocket) SetSelfId(_ context.Context, selfId int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.selfId = selfId
	return nil
}

func (e *emitterSocket) waitEchoBytes(ctx context.Context, echoID string, send func() error) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, EchoTimeOut)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.done == nil && !e.closed {
		e.done = make(chan struct{})
	}
	closed, done := e.closed, e.done
	e.mu.Unlock()
	if closed {
		return nil, errors.New("OneBot connection closed")
	}
	ch := make(chan []byte, 1)
	e.waiters.Store(echoID, ch)
	defer e.waiters.Delete(echoID)
	if err := send(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return nil, errors.New("OneBot connection closed")
	case raw := <-ch:
		return raw, nil
	}
}

func (e *emitterSocket) waitEchoAfterSend(ctx context.Context, action Action, echoID string, params any, send func() error) (Response[sonic.NoCopyRawMessage], error) {
	raw, err := e.waitEchoBytes(ctx, echoID, send)
	if err != nil {
		return Response[sonic.NoCopyRawMessage]{}, wrapActionError(err, action, echoID, params)
	}
	var response Response[sonic.NoCopyRawMessage]
	if err := sonic.Unmarshal(raw, &response); err != nil {
		return response, fmt.Errorf("decode OneBot response: %w", err)
	}
	return response, nil
}

type onebotActionRejectedError string

func (err onebotActionRejectedError) Error() string { return string(err) }
func (onebotActionRejectedError) IsActionRejected() {}

func decodeResponse[R any](action Action, echoId string, params any, resp Response[sonic.NoCopyRawMessage]) (*R, error) {
	if resp.RetCode != 0 || strings.EqualFold(resp.Status, "failed") {
		return nil, onebotActionRejectedError(fmt.Sprintf("OneBot 动作执行失败: action=%s echo=%s params=%s response=%s",
			action, echoId, marshalForError(params), marshalForError(resp)))
	}
	if !strings.EqualFold(resp.Status, "ok") {
		return nil, fmt.Errorf("OneBot 响应状态无法确认: action=%s echo=%s params=%s response=%s",
			action, echoId, marshalForError(params), marshalForError(resp))
	}
	var res R
	if err := sonic.Unmarshal(resp.Data, &res); err != nil {
		return nil, fmt.Errorf("解析 OneBot 响应失败: action=%s echo=%s params=%s response=%s err=%w",
			action, echoId, marshalForError(params), marshalForError(resp), err)
	}
	return &res, nil
}

func (e *emitterSocket) SendPvtMsg(ctx context.Context, userId int64, msg schema.MessageChain) (*types.SendMsgRes, error) {
	params := types.SendPrivateMsgReq{
		UserId:  userId,
		Message: msg,
	}
	resp, err := doAction(ctx, e, ACTION_SEND_PRIVATE_MSG, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.SendMsgRes](ACTION_SEND_PRIVATE_MSG, resp.Echo, params, resp)
}

func (e *emitterSocket) SendGrMsg(ctx context.Context, groupId int64, msg schema.MessageChain) (*types.SendMsgRes, error) {
	params := types.SendGrMsgReq{
		GroupId: groupId,
		Message: msg,
	}
	resp, err := doAction(ctx, e, ACTION_SEND_GROUP_MSG, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.SendMsgRes](ACTION_SEND_GROUP_MSG, resp.Echo, params, resp)
}

func (e *emitterSocket) GetMsg(ctx context.Context, msgId int64) (*types.GetMsgRes, error) {
	params := types.GetMsgReq{
		MessageId: msgId,
	}
	resp, err := doAction(ctx, e, ACTION_GET_MSG, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.GetMsgRes](ACTION_GET_MSG, resp.Echo, params, resp)
}

func (e *emitterSocket) DelMsg(ctx context.Context, msgId int64) error {
	params := types.DelMsgReq{
		MessageId: msgId,
	}
	resp, err := doAction(ctx, e, ACTION_DELETE_MSG, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_DELETE_MSG, resp.Echo, params, resp)
	return err
}

func (e *emitterSocket) GetLoginInfo(ctx context.Context) (*types.LoginInfo, error) {
	resp, err := doAction(ctx, e, ACTION_GET_LOGIN_INFO, nil)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.LoginInfo](ACTION_GET_LOGIN_INFO, resp.Echo, nil, resp)
}

func (e *emitterSocket) GetStrangerInfo(ctx context.Context, userId int64, noCache bool) (*types.StrangerInfo, error) {
	params := types.GetStrangerInfo{
		UserId:  userId,
		NoCache: noCache,
	}
	resp, err := doAction(ctx, e, ACTION_GET_STRANGER_INFO, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.StrangerInfo](ACTION_GET_STRANGER_INFO, resp.Echo, params, resp)
}

func (e *emitterSocket) GetStatus(ctx context.Context) (*types.Status, error) {
	resp, err := doAction(ctx, e, ACTION_GET_STATUS, nil)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.Status](ACTION_GET_STATUS, resp.Echo, nil, resp)
}

func (e *emitterSocket) GetVersionInfo(ctx context.Context) (*types.VersionInfo, error) {
	resp, err := doAction(ctx, e, ACTION_GET_VERSION_INFO, nil)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.VersionInfo](ACTION_GET_VERSION_INFO, resp.Echo, nil, resp)
}

func (e *emitterSocket) GetSelfId(_ context.Context) (int64, error) {
	return e.selfId, nil
}

func (e *emitterSocket) SetFriendAddRequest(ctx context.Context, flag string, approve bool, remark string) error {
	params := types.FriendAddReq{
		Flag:    flag,
		Approve: approve,
		Remark:  remark,
	}
	resp, err := doAction(ctx, e, ACTION_SET_FRIEND_ADD_REQUEST, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_SET_FRIEND_ADD_REQUEST, resp.Echo, params, resp)
	return err
}

func (e *emitterSocket) SetGroupAddRequest(ctx context.Context, flag string, subType string, approve bool, reason string) error {
	params := types.GroupAddReq{
		Flag:    flag,
		SubType: subType,
		Approve: approve,
		Reason:  reason,
	}
	resp, err := doAction(ctx, e, ACTION_SET_GROUP_ADD_REQUEST, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_SET_GROUP_ADD_REQUEST, resp.Echo, params, resp)
	return err
}

func (e *emitterSocket) SetGroupSpecialTitle(ctx context.Context, groupId int64, userId int64, specialTitle string, duration int) error {
	params := types.SpecialTitleReq{
		GroupId:      groupId,
		UserId:       userId,
		SpecialTitle: specialTitle,
	}
	resp, err := doAction(ctx, e, ACTION_SET_GROUP_SPECIAL_TITLE, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_SET_GROUP_SPECIAL_TITLE, resp.Echo, params, resp)
	return err
}

// ADD 不存在于Onebot大典的内容

func (e *emitterSocket) QuitGroup(ctx context.Context, groupId int64) error {
	params := types.QuitGroupReq{
		GroupId: groupId,
	}
	resp, err := doAction(ctx, e, ACTION_QUIT_GROUP, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_QUIT_GROUP, resp.Echo, params, resp)
	return err
}

func (e *emitterSocket) SetGroupCard(ctx context.Context, groupId int64, userId int64, card string) error {
	params := types.SetGroupCardReq{
		GroupId: groupId,
		UserId:  userId,
		Card:    card,
	}
	resp, err := doAction(ctx, e, ACTION_SET_GROUP_CARD, params)
	if err != nil {
		return err
	}
	_, err = decodeResponse[any](ACTION_SET_GROUP_CARD, resp.Echo, params, resp)
	return err
}

func (e *emitterSocket) GetGroupInfo(ctx context.Context, groupId int64, noCache bool) (*types.GroupInfo, error) {
	params := types.GetGroupInfoReq{
		GroupId: groupId,
		NoCache: noCache,
	}
	resp, err := doAction(ctx, e, ACTION_GET_GROUP_INFO, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.GroupInfo](ACTION_GET_GROUP_INFO, resp.Echo, params, resp)
}

func (e *emitterSocket) GetGroupMemberInfo(ctx context.Context, groupId int64, userId int64, noCache bool) (*types.GroupMemberInfo, error) {
	params := types.GetGroupMemberInfoReq{
		GroupId: groupId,
		UserId:  userId,
		NoCache: noCache,
	}
	resp, err := doAction(ctx, e, ACTION_GET_GROUP_MEMBER_INFO, params)
	if err != nil {
		return nil, err
	}
	return decodeResponse[types.GroupMemberInfo](ACTION_GET_GROUP_MEMBER_INFO, resp.Echo, params, resp)
}

func (e *emitterSocket) Raw(ctx context.Context, action Action, params any) ([]byte, error) {
	echoID := uuid.NewString()
	request, err := sonic.Marshal(Request[any]{Action: action, Params: params, Echo: echoID})
	if err != nil {
		return nil, err
	}
	return e.sendRawRequest(ctx, echoID, request)
}

// RawJSON preserves all provider fields. Only the reserved correlation echo is
// replaced; a protocol-level failure is still a response, not a transport error.
func (e *emitterSocket) RawJSON(ctx context.Context, request []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(request, &envelope); err != nil || envelope == nil {
		return nil, fmt.Errorf("%w: request must be a JSON object", ErrInvalidRawRequest)
	}
	var action string
	if json.Unmarshal(envelope["action"], &action) != nil || strings.TrimSpace(action) == "" {
		return nil, fmt.Errorf("%w: request requires an action", ErrInvalidRawRequest)
	}
	echoID := uuid.NewString()
	echoJSON, _ := json.Marshal(echoID)
	envelope["echo"] = echoJSON
	wire, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(wire) > adapterapi.MaxProtocolJSONBytes {
		return nil, fmt.Errorf("%w: request with correlation echo exceeds bounds", ErrInvalidRawRequest)
	}
	return e.sendRawRequest(ctx, echoID, wire)
}

func (e *emitterSocket) sendRawRequest(ctx context.Context, echoID string, wire []byte) ([]byte, error) {
	return e.waitEchoBytes(ctx, echoID, func() error {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.closed || e.conn == nil || !e.conn.IsAlive() {
			return errors.New("OneBot connection unavailable")
		}
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		e.conn.Emit(wire, socketio.TextMessage)
		return nil
	})
}

func doAction(ctx context.Context, e *emitterSocket, action string, params any) (Response[sonic.NoCopyRawMessage], error) {
	echoId := uuid.New().String()
	resp, err := e.waitEchoAfterSend(ctx, action, echoId, params, func() error {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.closed || e.conn == nil || !e.conn.IsAlive() {
			return errors.New("OneBot connection unavailable")
		}
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return wsEmitWithEcho(e.conn, action, params, echoId)
	})
	if err != nil {
		return Response[sonic.NoCopyRawMessage]{}, err
	}
	return resp, nil
}

func wrapActionError(err error, action Action, echoId string, params any) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("等待 OneBot Echo 超时: action=%s echo=%s params=%s err=%w",
			action, echoId, marshalForError(params), err)
	}
	return fmt.Errorf("执行 OneBot 动作失败: action=%s echo=%s params=%s err=%w",
		action, echoId, marshalForError(params), err)
}

func marshalForError(value any) string {
	if value == nil {
		return "null"
	}
	data, err := sonic.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(data)
}

func wsEmitWithEcho(w *socketio.WebsocketWrapper, action string, params any, echoId string) error {
	marshal, err := sonic.Marshal(Request[any]{
		Action: action,
		Echo:   echoId,
		Params: params,
	})
	if err != nil {
		return err
	}
	w.Emit(marshal, socketio.TextMessage)
	return nil
}
