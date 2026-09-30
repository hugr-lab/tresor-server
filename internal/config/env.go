package config

// The configuration from the environment (spec 002): the file, then TRESOR_CONFIG (a whole YAML document),
// then one TRESOR_<PATH> variable per setting (`__` between levels), each over the last. The result is
// validated as a file is. A text setting takes its variable's value as it is; a list, a section or a
// number is read as YAML.

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

// ErrEmpty: no file and no TRESOR_ setting - nothing to run with.
var ErrEmpty = errors.New("config: no configuration - give -config <file>, TRESOR_CONFIG, or TRESOR_<SETTING> variables")

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

type envSetting struct {
	name  string
	path  []string
	value string
}

// LoadFrom is Load with the file's content and the environment given ("NAME=value" entries).
func LoadFrom(file []byte, environ []string) (*Config, FromEnv, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if err := mergeDocument(root, file, "the file"); err != nil {
		return nil, nil, err
	}
	var used FromEnv
	var settings []envSetting
	seen := map[string]string{} // the folded path -> the variable that set it
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, envPrefix) {
			continue
		}
		if name == envDocument {
			if err := mergeDocument(root, []byte(value), envDocument); err != nil {
				return nil, nil, err
			}
			used = append(used, envDocument)
			continue
		}
		path, isSetting, err := settingPath(name)
		if err != nil {
			return nil, nil, err
		}
		if !isSetting {
			continue // not a setting: a variable a setting names, a test's, another tool's
		}
		key := strings.Join(path, envLevel)
		if other, dup := seen[key]; dup {
			return nil, nil, fmt.Errorf("config: %s and %s set the same setting", other, name)
		}
		seen[key] = name
		settings = append(settings, envSetting{name: name, path: path, value: value})
	}
	// a section before its keys: TRESOR_STATE, then TRESOR_STATE__KIND over it
	sort.Slice(settings, func(i, j int) bool {
		if len(settings[i].path) != len(settings[j].path) {
			return len(settings[i].path) < len(settings[j].path)
		}
		return strings.Join(settings[i].path, envLevel) < strings.Join(settings[j].path, envLevel)
	})
	for _, s := range settings {
		node, err := settingValue(s)
		if err != nil {
			return nil, nil, err
		}
		set(root, s.path, node)
		used = append(used, s.name)
	}
	if len(root.Content) == 0 {
		return nil, nil, ErrEmpty
	}
	data, err := yaml.Marshal(root)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(used)
	return cfg, used, nil
}

// settingPath is the setting a TRESOR_ variable names. A variable whose name is not a setting's shape (not
// a top-level setting, no `__`, not a top-level setting and `_`) is not configuration; one of that shape
// that names no setting is an error - a typo must not be ignored.
func settingPath(name string) (path []string, isSetting bool, err error) {
	rest := strings.ToLower(strings.TrimPrefix(name, envPrefix))
	path = strings.Split(rest, envLevel)
	top := topLevelKeys()
	if !top[path[0]] {
		looksLikeOne := len(path) > 1
		for key := range top {
			looksLikeOne = looksLikeOne || strings.HasPrefix(rest, key+"_")
		}
		if looksLikeOne {
			return nil, false, fmt.Errorf("config: %s names no setting (TRESOR_<SETTING>, `__` between levels)", name)
		}
		return nil, false, nil
	}
	if _, err := fieldAt(path); err != nil {
		return nil, false, fmt.Errorf("config: %s: %w", name, err)
	}
	return path, true, nil
}

// settingValue is a variable's value as a node: as it is for a text setting, read as YAML otherwise.
func settingValue(s envSetting) (*yaml.Node, error) {
	t, _ := fieldAt(s.path)
	if t.Kind() == reflect.String {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s.value}, nil
	}
	var value yaml.Node
	if err := yaml.Unmarshal([]byte(s.value), &value); err != nil {
		return nil, fmt.Errorf("config: %s is not YAML: %w", s.name, redact(err))
	}
	if len(value.Content) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}, nil
	}
	return resolveAliases(value.Content[0])
}

// fieldAt is the type of the setting at path, following Config's yaml tags. A list's items cannot be named
// one by one: a list is given whole.
func fieldAt(path []string) (reflect.Type, error) {
	t := reflect.TypeOf(Config{})
	for i, part := range path {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || t == reflect.TypeOf(yaml.Node{}) {
			if t.Kind() == reflect.Slice {
				return nil, fmt.Errorf("%s is a list: give it whole, not by item", strings.Join(path[:i], "."))
			}
			return nil, fmt.Errorf("%s has no settings under it", strings.Join(path[:i], "."))
		}
		field, ok := fieldByTag(t, part)
		if !ok {
			return nil, fmt.Errorf("no setting %s", strings.Join(path[:i+1], "."))
		}
		t = field.Type
	}
	return t, nil
}

func fieldByTag(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		if tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ","); tag == name && tag != "-" {
			return t.Field(i), true
		}
	}
	return reflect.StructField{}, false
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

// IsSettingVariable says whether an environment variable would be read as configuration: a *_env setting
// must not name one, or its secret would be configuration too.
func IsSettingVariable(name string) bool {
	if name == envDocument {
		return true
	}
	if !strings.HasPrefix(name, envPrefix) {
		return false
	}
	path, isSetting, err := settingPath(name)
	return err != nil || (isSetting && len(path) > 0)
}

// mergeDocument merges a YAML document (a mapping, or nothing) into root, its aliases resolved first.
func mergeDocument(root *yaml.Node, data []byte, from string) error {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config: %s: %w", from, redact(err))
	}
	if len(doc.Content) == 0 {
		return nil
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config: %s is not a mapping of settings", from)
	}
	resolved, err := resolveAliases(doc.Content[0])
	if err != nil {
		return fmt.Errorf("config: %s: %w", from, err)
	}
	merge(root, resolved)
	return nil
}

// resolveAliases copies a node with every alias replaced by what it names: a node overridden by a variable
// may be an anchor another part of the document refers to.
func resolveAliases(node *yaml.Node) (*yaml.Node, error) {
	var walk func(n *yaml.Node, depth int) (*yaml.Node, error)
	walk = func(n *yaml.Node, depth int) (*yaml.Node, error) {
		if depth > 64 {
			return nil, errors.New("aliases nested too deep")
		}
		if n.Kind == yaml.AliasNode {
			return walk(n.Alias, depth+1)
		}
		out := *n
		out.Anchor = ""
		out.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			var err error
			if out.Content[i], err = walk(c, depth+1); err != nil {
				return nil, err
			}
		}
		return &out, nil
	}
	return walk(node, 0)
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

// redact keeps a YAML syntax error's line and drops the text it quotes: the value may be a secret by mistake.
func redact(err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "yaml: line ") {
		if i := strings.Index(msg, ": "); i >= 0 {
			if j := strings.Index(msg[i+2:], ":"); j >= 0 {
				return errors.New(msg[:i+2+j] + ": malformed")
			}
		}
	}
	return errors.New("malformed")
}
