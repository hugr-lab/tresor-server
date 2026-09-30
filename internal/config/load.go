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
	v.AllowEmptyEnv(true) // an empty variable is an empty text, not ignored
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
		for _, path := range settingPaths() {
			name := envPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", envLevel))
			if err := v.BindEnv(path, name); err != nil {
				return nil, nil, fmt.Errorf("config: %w", err)
			}
			if _, ok := os.LookupEnv(name); ok {
				used = append(used, name)
			}
		}
	}
	if len(bytes.TrimSpace(data)) == 0 && len(used) == 0 { // (AllKeys lists every bound variable, set or not)
		return nil, nil, ErrEmpty
	}
	var cfg Config
	err = v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) {
		c.TagName = "yaml"
		c.WeaklyTypedInput = false // `audience: 0123` must not become "83": a number for a text is an error
		c.DecodeHook = typed
	})
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", unquoted(err))
	}
	if legacyStore && cfg.Store == nil {
		cfg.Store = map[string]any{} // an empty `store:` is still the reference server's
	}
	if withEnv {
		if err := checkEnvNames(os.Environ(), secretVariables(&cfg)); err != nil {
			return nil, nil, err
		}
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
	// viper folds keys to lower case and splits them at dots: the document is checked as written first -
	// its keys exact, none twice, none unknown
	var strict Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&strict); err != nil {
		return false, fmt.Errorf("config: %s: %w", from, decodeError(err))
	}
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
func checkEnvNames(environ []string, secrets map[string]bool) error {
	top := map[string]bool{}
	bound := map[string]bool{}
	for _, path := range settingPaths() {
		first, _, _ := strings.Cut(path, ".")
		top[first] = true
		bound[envPrefix+strings.ToUpper(strings.ReplaceAll(path, ".", envLevel))] = true
	}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(strings.ToUpper(name), envPrefix) || name == envDocument {
			continue
		}
		if bound[name] || secrets[name] {
			continue // a setting's, or a secret's a *_env setting names
		}
		if bound[strings.ToUpper(name)] {
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

// typed decodes with no weak conversion: a variable's text is read as YAML where a list, a mapping, a
// section or a flag is wanted (a file's values come typed already); a text setting takes a text only - a
// number or a flag there is an error, to be quoted.
func typed(from, to reflect.Type, data any) (any, error) {
	if to.Kind() == reflect.String && from.Kind() != reflect.String {
		return nil, fmt.Errorf("a %s where a text belongs - quote it", from.Kind())
	}
	if from.Kind() != reflect.String {
		return data, nil
	}
	switch to.Kind() {
	case reflect.Slice, reflect.Map, reflect.Struct, reflect.Bool, reflect.Pointer:
	default:
		return data, nil
	}
	var out any
	if err := yaml.Unmarshal([]byte(data.(string)), &out); err != nil {
		return nil, fmt.Errorf("not YAML (%s)", yamlLine(err))
	}
	return out, nil
}

// secretVariables are the variables *_env settings name: secrets, never configuration.
func secretVariables(cfg *Config) map[string]bool {
	out := map[string]bool{}
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Slice:
			for i := range v.Len() {
				walk(v.Index(i))
			}
		case reflect.Struct:
			for i := range v.NumField() {
				tag, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("yaml"), ",")
				if strings.HasSuffix(tag, "_env") && v.Field(i).Kind() == reflect.String && v.Field(i).String() != "" {
					out[v.Field(i).String()] = true
				}
				walk(v.Field(i))
			}
		}
	}
	walk(reflect.ValueOf(cfg))
	return out
}

// typeError is one entry of a yaml.TypeError: its line, what was found and what was wanted - the value it
// quotes in between is dropped (a secret put in the wrong place must not reach the log).
var typeError = regexp.MustCompile(`(?s)^(line \d+): cannot unmarshal (\S+) .* into (\S+)$`)

func decodeError(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return errors.New(yamlLine(err))
	}
	out := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		switch m := typeError.FindStringSubmatch(e); {
		case m != nil:
			out = append(out, fmt.Sprintf("%s: a %s where a %s belongs", m[1], m[2], m[3]))
		case strings.Contains(e, ": field ") && strings.Contains(e, " not found in type "):
			out = append(out, e) // an unknown key: the key's name, as the document's author wrote it
		default:
			line, _, _ := strings.Cut(e, ":")
			out = append(out, line+": invalid")
		}
	}
	return errors.New(strings.Join(out, "; "))
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
