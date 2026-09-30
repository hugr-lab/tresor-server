package config

// Loading (spec 002), through viper: the file, then TRESOR_CONFIG (a whole YAML document), then one
// TRESOR_<PATH> variable per setting (`__` between levels), each over the last. What viper leaves to us is
// the service's policy: a TRESOR_ name that looks like a setting but names none is an error, a text setting
// takes its variable as it is (a list or a section is read as YAML), and no error quotes a value.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
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

// Load reads the configuration: the file (none when file is ""), then the environment.
func Load(file string) (*Config, FromEnv, error) {
	var data []byte
	if file != "" {
		var err error
		if data, err = os.ReadFile(file); err != nil {
			return nil, nil, err
		}
	}
	return load(data, true)
}

// Parse reads and validates a YAML document alone, with no environment (tests, tools).
func Parse(data []byte) (*Config, error) {
	cfg, _, err := load(data, false)
	return cfg, err
}

func load(data []byte, withEnv bool) (*Config, FromEnv, error) {
	v := viper.NewWithOptions(viper.KeyDelimiter("."))
	v.SetConfigType("yaml")
	legacyStore, err := readDocument(v, data, "the file", false)
	if err != nil {
		return nil, nil, err
	}
	var used FromEnv
	if withEnv {
		if doc, ok := os.LookupEnv(envDocument); ok {
			inDoc, err := readDocument(v, []byte(doc), envDocument, true)
			if err != nil {
				return nil, nil, err
			}
			legacyStore = legacyStore || inDoc
			used = append(used, envDocument)
		}
		bound := map[string]string{} // variable -> setting path
		for _, path := range settingPaths() {
			name := envPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", envLevel))
			bound[name] = path
			if err := v.BindEnv(path, name); err != nil {
				return nil, nil, fmt.Errorf("config: %w", err)
			}
			if _, ok := os.LookupEnv(name); ok {
				used = append(used, name)
			}
		}
		if err := checkEnvNames(os.Environ(), bound); err != nil {
			return nil, nil, err
		}
	}
	if len(bytes.TrimSpace(data)) == 0 && len(used) == 0 { // (AllKeys lists every bound variable, set or not)
		return nil, nil, ErrEmpty
	}
	var cfg Config
	err = v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) {
		c.TagName = "yaml"
		c.DecodeHook = yamlForStructured
	})
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", unquoted(err))
	}
	if legacyStore && cfg.Store == nil {
		cfg.Store = map[string]any{} // an empty `store:` is still the reference server's
	}
	if err := cfg.validate(); err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	sort.Strings(used)
	return &cfg, used, nil
}

// readDocument merges a YAML document into v; it says whether the document has a `store:` key, even empty
// (viper drops a key whose value is empty).
func readDocument(v *viper.Viper, data []byte, from string, merge bool) (bool, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return false, nil
	}
	var top map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil {
		return false, fmt.Errorf("config: %s is not a YAML mapping of settings (%s)", from, yamlLine(err))
	}
	_, store := top["store"]
	read := v.ReadConfig
	if merge {
		read = v.MergeConfig
	}
	if err := read(bytes.NewReader(data)); err != nil {
		return false, fmt.Errorf("config: %s: %s", from, yamlLine(err))
	}
	return store, nil
}

// settingPaths are the paths an environment variable can set: every setting that is not a section of
// settings - a text, a number, a list (given whole), a mapping.
func settingPaths() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			ft := t.Field(i).Type
			if ft.Kind() == reflect.Struct {
				walk(ft, prefix+name+".")
				continue
			}
			out = append(out, prefix+name)
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	return out
}

// checkEnvNames refuses a TRESOR_ variable that looks like a setting but names none: a typo must not be
// ignored. A variable not of a setting's shape (TRESOR_EXCHANGE_SECRET, tresor's test variables) is left
// alone.
func checkEnvNames(environ []string, bound map[string]string) error {
	top := map[string]bool{}
	for _, path := range settingPaths() {
		first, _, _ := strings.Cut(path, ".")
		top[first] = true
	}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(strings.ToUpper(name), envPrefix) || name == envDocument {
			continue
		}
		if _, ok := bound[name]; ok {
			continue
		}
		if _, ok := bound[strings.ToUpper(name)]; ok {
			return fmt.Errorf("config: %s: a setting's variable is in capitals (%s)", name, strings.ToUpper(name))
		}
		rest := strings.ToLower(name[len(envPrefix):])
		looksLikeOne := strings.Contains(rest, envLevel)
		for key := range top {
			looksLikeOne = looksLikeOne || rest == key || strings.HasPrefix(rest, key+"_")
		}
		if looksLikeOne {
			return fmt.Errorf("config: %s names no setting (TRESOR_<SETTING>, `__` between levels; a list is given "+
				"whole, a section by its keys or in TRESOR_CONFIG)", name)
		}
	}
	return nil
}

// IsSettingVariable says whether an environment variable is read as configuration: a *_env setting must not
// name one, or its secret would be configuration too.
func IsSettingVariable(name string) bool {
	if name == envDocument {
		return true
	}
	for _, path := range settingPaths() {
		if name == envPrefix+strings.ToUpper(strings.ReplaceAll(path, ".", envLevel)) {
			return true
		}
	}
	return false
}

// yamlForStructured reads a text as YAML where a list, a mapping or a section is wanted (a variable's value;
// a file's values come typed already). A text setting takes the text as it is.
func yamlForStructured(from, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}
	switch to.Kind() {
	case reflect.Slice, reflect.Map, reflect.Struct:
	default:
		return data, nil
	}
	var out any
	if err := yaml.Unmarshal([]byte(data.(string)), &out); err != nil {
		return nil, fmt.Errorf("not YAML (%s)", yamlLine(err))
	}
	return out, nil
}

// the value mapstructure quotes after the setting's name, and a YAML error's quoted text
var (
	quotedValue = regexp.MustCompile(`(?s)(expected type '[^']*'), got .*`)
	lineOnly    = regexp.MustCompile(`line \d+`)
)

// unquoted is a decode error with no value in it: a secret put in the wrong place must not reach the log.
func unquoted(err error) error {
	var lines []string
	for line := range strings.SplitSeq(err.Error(), "\n") {
		lines = append(lines, quotedValue.ReplaceAllString(line, "$1"))
	}
	return errors.New(strings.Join(slices.DeleteFunc(lines, func(l string) bool { return strings.TrimSpace(l) == "" }), "; "))
}

// yamlLine is a YAML error reduced to its line: its text may quote the value.
func yamlLine(err error) string {
	if line := lineOnly.FindString(err.Error()); line != "" {
		return "malformed at " + line
	}
	return "malformed"
}
