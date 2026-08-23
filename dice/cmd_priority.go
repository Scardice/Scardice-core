package dice

import "strings"

// commandExtensionOrder returns activated extensions in command-resolution
// order. Extensions related to the current game system are promoted as one
// stable tier; all relative ordering inside and outside that tier is retained.
func commandExtensionOrder(group *GroupInfo, d *Dice) []*ExtInfo {
	if group == nil || d == nil {
		return nil
	}

	activated := group.GetActivatedExtList(d)
	preferred := commandPreferredExtNames(group, d)
	if len(preferred) == 0 {
		return activated
	}

	ordered := make([]*ExtInfo, 0, len(activated))
	for _, ext := range activated {
		if ext == nil {
			continue
		}
		if _, ok := preferred[strings.ToLower(ext.Name)]; ok {
			ordered = append(ordered, ext)
		}
	}
	for _, ext := range activated {
		if ext == nil {
			continue
		}
		if _, ok := preferred[strings.ToLower(ext.Name)]; !ok {
			ordered = append(ordered, ext)
		}
	}
	return ordered
}

// commandPreferredExtNames 返回当前规则模板关联的扩展名集合（含链式关联，全部小写）。
// 该集合即 commandExtensionOrder 提升到前列的那一层，同时用于指令候选择优。
func commandPreferredExtNames(group *GroupInfo, d *Dice) map[string]struct{} {
	if group == nil || d == nil || group.System == "" || d.GameSystemMap == nil {
		return nil
	}

	tmpl, ok := d.GameSystemMap.Load(group.System)
	if !ok || tmpl == nil {
		return nil
	}
	relatedExt := tmpl.Commands.Set.RelatedExt
	if len(relatedExt) == 0 {
		relatedExt = tmpl.SetConfig.RelatedExt
	}
	if len(relatedExt) == 0 {
		return nil
	}

	preferred := make(map[string]struct{}, len(relatedExt))
	graph := d.activeWithGraph()
	for _, related := range relatedExt {
		related = strings.TrimSpace(related)
		if related == "" {
			continue
		}

		name := d.ExtAliasToName(related)
		preferred[strings.ToLower(name)] = struct{}{}
		for _, chained := range collectChainedNames(d.Logger, graph, name, maxChainDepth) {
			preferred[strings.ToLower(chained)] = struct{}{}
		}
	}
	if len(preferred) == 0 {
		return nil
	}
	return preferred
}
