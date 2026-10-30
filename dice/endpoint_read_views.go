package dice

import (
	"context"
	"encoding/json"
	"sort"

	"Scardice-core/adapterapi"
	endpointstate "Scardice-core/endpoint"
)

// EndPointsReadOnly reconstructs compatibility DTOs from the authoritative
// endpoint projection. Returned pointers are detached and must never be used as
// configuration or lifecycle owners.
func (s *IMSession) EndPointsReadOnly() []*EndPointInfo {
	if s == nil || s.Parent == nil || s.Parent.DurableStore == nil {
		return nil
	}
	lister, ok := s.Parent.DurableStore.(eventSourcedProjectionLister)
	if !ok {
		return nil
	}
	rows, err := lister.ListProjectionRows(context.Background(), endpointstate.EndpointProjectionName)
	if err != nil {
		if s.Parent.Logger != nil {
			s.Parent.Logger.Errorf("读取 endpoint projection 失败: %v", err)
		}
		return nil
	}
	publicEndpointIDs := make(map[string]struct{}, len(s.Parent.Config.EndpointIDs))
	for _, endpointID := range s.Parent.Config.EndpointIDs {
		publicEndpointIDs[endpointID] = struct{}{}
	}
	views := make([]*EndPointInfo, 0, len(rows))
	for _, row := range rows {
		var projected endpointstate.EndpointView
		if err = json.Unmarshal(row.Payload, &projected); err != nil || projected.EndpointID == "" {
			if s.Parent.Logger != nil {
				s.Parent.Logger.Errorf("解析 endpoint projection %q 失败: %v", row.RowKey, err)
			}
			return nil
		}
		platform, protocol := compatibilityEndpointNames(projected.AdapterKey)
		endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
			ID: string(projected.EndpointID), Nickname: projected.DisplayName, Platform: platform, ProtocolType: protocol,
			UserID: string(projected.ProviderID), GroupNum: projected.Statistics.GroupCount,
			CmdExecutedNum: projected.Statistics.CommandCount, CmdExecutedLastTime: projected.Statistics.LastCommandAt,
			OnlineTotalTime: projected.Statistics.OnlineSeconds,
			Enable:          projected.DesiredState == endpointstate.DesiredStateEnabled,
			State:           compatibilityEndpointState(projected.ObservedState), Session: s,
		}}
		_, endpoint.IsPublic = publicEndpointIDs[endpoint.ID]
		var canonical map[string]any
		if endpoint.UserID == "" && json.Unmarshal(projected.Config.Canonical, &canonical) == nil {
			if account, accountOK := canonical["accountHint"].(string); accountOK {
				endpoint.UserID = account
			}
		}
		views = append(views, endpoint)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	return views
}

func compatibilityEndpointState(state adapterapi.ObservedState) EndpointState {
	switch state {
	case adapterapi.ObservedStateConnected:
		return StateConnected
	case adapterapi.ObservedStateStarting, adapterapi.ObservedStateStopping:
		return StateConnecting
	case adapterapi.ObservedStateFailed:
		return StateConnectionFailed
	case adapterapi.ObservedStateInvalid, adapterapi.ObservedStateStopped, adapterapi.ObservedStateAmbiguous:
		return StateDisconnected
	default:
		return StateDisconnected
	}
}

func compatibilityEndpointNames(key adapterapi.AdapterKey) (platform, protocol string) {
	protocol = string(key)
	switch key {
	case OfficialQQAdapterKey:
		return "QQ", "official"
	case OnebotAdapterKey, GocqAdapterKey, LagrangeAdapterKey, WalleQAdapterKey, MilkyAdapterKey, RedAdapterKey:
		return "QQ", protocol
	case DiscordAdapterKey:
		return "DISCORD", protocol
	case KookAdapterKey:
		return "KOOK", protocol
	case TelegramAdapterKey:
		return "TG", protocol
	case SlackAdapterKey:
		return "SLACK", protocol
	case DodoAdapterKey:
		return "DODO", protocol
	case DingTalkAdapterKey:
		return "DINGTALK", protocol
	case MinecraftAdapterKey:
		return "MC", protocol
	case SatoriAdapterKey:
		return "SATORI", protocol
	case SealChatAdapterKey:
		return "SEALCHAT", protocol
	case HTTPAdapterKey:
		return "HTTP", protocol
	default:
		return "", protocol
	}
}
