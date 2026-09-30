package config

// The configuration from the environment (spec 002): the file, then TRESOR_CONFIG (a whole YAML document),
// then one TRESOR_<PATH> variable per setting (`__` between levels, the value read as YAML), each over the
// last. The result is validated as a file is.

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	envPrefix   = "TRESOR_"
	envDocument = "TRESOR_CONFIG"
	envLevel    = "__"
)

// FromEnv lists the settings a configuration took from the environment: variable names, never values.
type FromEnv []string

// Load reads the configuration: the file (none when file is ""), then the environment (os.Environ).
func Load(file string) (*Config, FromEnv, error) {
	var data []byte
	if file != "" {
		var err error
		if data, err = os.ReadFile(file); err != nil {
			return nil, nil, err
		}
	}
	return LoadFrom(data, os.Environ())
}

// LoadFrom is Load with the file's content and the environment given ("NAME=value" entries).
func LoadFrom(file []byte, environ []string) (*Config, FromEnv, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if err := mergeDocument(root, file, "the file"); err != nil {
		return nil, nil, err
	}
	env := map[string]string{}
	for _, kv := range environ {
		if name, value, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, envPrefix) {
			env[name] = value
		}
	}
	var used FromEnv
	if doc, ok := env[envDocument]; ok {
		if err := mergeDocument(root, []byte(doc), envDocument); err != nil {
			return nil, nil, err
		}
		used = append(used, envDocument)
	}
	top := topLevelKeys()
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names) // a shorter path first: TRESOR_STATE, then TRESOR_STATE__KIND over it
	for _, name := range names {
		path := strings.Split(strings.ToLower(strings.TrimPrefix(name, envPrefix)), envLevel)
		if name == envDocument || !top[path[0]] {
			continue // not a setting: a variable a setting names, a test's, another tool's
		}
		for _, part := range path {
			if part == "" {
				return nil, nil, fmt.Errorf("config: %s: an empty level in the name", name)
			}
		}
		var value yaml.Node
		if err := yaml.Unmarshal([]byte(env[name]), &value); err != nil {
			return nil, nil, fmt.Errorf("config: %s is not YAML: %w", name, redact(err))
		}
		node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""} // an empty variable: an empty text
		if len(value.Content) > 0 {
			node = value.Content[0]
		}
		set(root, path, node)
		used = append(used, name)
	}
	data, err := yaml.Marshal(root)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return cfg, used, nil
}

// mergeDocument merges a YAML document (a mapping, or nothing) into root.
func mergeDocument(root *yaml.Node, data []byte, from string) error {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config: %s: %w", from, err)
	}
	if len(doc.Content) == 0 {
		return nil
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config: %s is not a mapping of settings", from)
	}
	merge(root, doc.Content[0])
	return nil
}

// merge lays src over dst: mappings key by key, anything else replaced whole (a list is not merged).
func merge(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i], src.Content[i+1]
		if j := find(dst, key.Value); j >= 0 {
			if dst.Content[j].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
				merge(dst.Content[j], value)
			} else {
				dst.Content[j] = value
			}
			continue
		}
		dst.Content = append(dst.Content, key, value)
	}
}

// set puts value at path in root, making the mappings on the way (a scalar on the way is replaced).
func set(root *yaml.Node, path []string, value *yaml.Node) {
	node := root
	for i, part := range path {
		j := find(node, part)
		if i == len(path)-1 {
			if j >= 0 {
				node.Content[j] = value
			} else {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, value)
			}
			return
		}
		if j < 0 || node.Content[j].Kind != yaml.MappingNode {
			next := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			if j >= 0 {
				node.Content[j] = next
			} else {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, next)
			}
			node = next
			continue
		}
		node = node.Content[j]
	}
}

// find is the index of key's value in a mapping node, or -1.
func find(mapping *yaml.Node, key string) int {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return i + 1
		}
	}
	return -1
}

// topLevelKeys are the settings' top-level names, from Config's yaml tags.
func topLevelKeys() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(Config{})
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ","); name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}

// redact keeps a YAML error's position and drops the text it quotes: the value may be a secret by mistake.
func redact(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return errors.New("a type error")
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "yaml: line") {
		return errors.New(msg[:i])
	}
	return errors.New("malformed")
}
