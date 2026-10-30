package censor

import "unicode/utf8"

type node struct {
	end      bool
	content  string
	level    Level
	children map[rune]*node
}

func (n *node) insert(c rune) *node {
	if n.children == nil {
		n.children = make(map[rune]*node)
	}
	if cur, ok := n.children[c]; ok {
		return cur
	}
	n.children[c] = &node{}
	return n.children[c]
}

func (n *node) findChild(c rune) *node {
	if n.children == nil {
		return nil
	}
	if cur, ok := n.children[c]; ok {
		return cur
	}
	return nil
}

type trie struct {
	root *node
	size int
}

func newTire() *trie {
	return &trie{
		root: &node{},
	}
}

func (t *trie) Insert(key string, level Level) {
	cur := t.root
	for _, c := range key {
		cur = cur.insert(c)
	}
	cur.end = true
	cur.content = key
	cur.level = HigherLevel(level, cur.level)
	t.size++
}

func (t *trie) Match(text string) (sensitiveWords map[string]Level) {
	if t.root == nil {
		return nil
	}

	sensitiveWords = map[string]Level{}
	for i, char := range text {
		cur := t.root.findChild(char)
		if cur == nil {
			continue
		}
		if cur.end {
			sensitiveWords[cur.content] = cur.level
			continue
		}
		size := 1
		if char >= utf8.RuneSelf {
			_, size = utf8.DecodeRuneInString(text[i:])
		}
		for _, next := range text[i+size:] {
			cur = cur.findChild(next)
			if cur == nil {
				break
			}
			if cur.end {
				sensitiveWords[cur.content] = cur.level
				break
			}
		}
	}
	return sensitiveWords
}
