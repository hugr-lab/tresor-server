package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// Variables (spec 004, tresor spec 018): named strings, the secrets' rules - names, grants, conditional writes -
// in a namespace of their own (state.Store.Variables). A variable is a state.Secret of type variable whose
// params hold "value", sealed at rest as a secret's are. A value that is a reference (ref+...) is resolved at
// each read, and its variable is sensitive: Provider says so without opening the value.

const (
	// maxVariableBytes is what the protocol says a service always accepts; more is refused.
	maxVariableBytes = 64 << 10
	variableType     = "variable"
	// providerReference marks a variable whose value is a reference: sensitive, read without opening it.
	providerReference = "reference"
)

func variableDescriptor(sec *state.Secret, verbs []string) map[string]any {
	if verbs == nil {
		verbs = []string{}
	}
	return map[string]any{
		"name":        sec.Name,
		"comment":     sec.Comment,
		"owner":       sec.Owner,
		"created_at":  sec.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":  sec.UpdatedAt.UTC().Format(time.RFC3339),
		"version":     strconv.FormatInt(sec.Version, 10),
		"sensitive":   sec.Provider == providerReference,
		"permissions": verbs,
	}
}

func (s *Server) listVariables(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	vars, err := s.store.Variables().List(r.Context())
	if err != nil {
		s.unavailable(w, "read", "", err)
		return
	}
	out := []map[string]any{}
	for _, v := range vars {
		if verbs := s.verbs(c, v); len(verbs) > 0 {
			out = append(out, variableDescriptor(v, verbs))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getVariable(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	v, verbs, ok := s.visible(w, r, c, r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "use") {
		s.refuse(w, c, "use")
		return
	}
	full, err := s.store.Variables().Get(r.Context(), v.Name)
	if errors.Is(err, state.ErrNotFound) { // dropped meanwhile
		problem(w, http.StatusNotFound, "not_found", "no variable "+strconv.Quote(v.Name))
		return
	}
	if err != nil {
		s.unavailable(w, "read", v.Name, err)
		return
	}
	// a reference is read now, with the service's identity; one that does not resolve fails the read - 503 when
	// it may later, 500 when it will not (outside the allowlist now) - never an empty or a stale value
	params, resolved, err := s.material.Resolve(r.Context(), full.Params)
	if err != nil {
		s.log.Error("a reference did not resolve", "variable", v.Name, "error", err.Error())
		if errors.Is(err, material.ErrInvalid) {
			problem(w, http.StatusInternalServerError, "service_error", "the variable's reference will not resolve")
			return
		}
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the variable's reference did not resolve")
		return
	}
	for _, res := range resolved { // where and which version, never the value
		s.log.Info("reference resolved", "variable", v.Name, "ref", res.Ref.String(), "version", res.Version)
	}
	var value string
	if err := json.Unmarshal(params["value"], &value); err != nil {
		s.log.Error("a variable's value does not read", "variable", v.Name)
		problem(w, http.StatusInternalServerError, "service_error", "the variable's value does not read")
		return
	}
	body := variableDescriptor(full, verbs)
	body["value"] = value
	if len(resolved) > 0 {
		body["sensitive"] = true // what was resolved is material, whatever the stored marker says
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(full.Version, 10)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) putVariable(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	name := r.PathValue("name")
	if err := validName("the variable's name", name); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	var body struct {
		Value   *string `json:"value"`
		Comment *string `json:"comment"`
	}
	if err := readJSON(r, &body); err != nil || body.Value == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a variable is {value, comment?}")
		return
	}
	if !utf8.ValidString(*body.Value) || len(*body.Value) > maxVariableBytes {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a variable's value is UTF-8, up to 64 KiB")
		return
	}
	value, _ := json.Marshal(*body.Value)
	params := map[string]json.RawMessage{"value": value}
	// a reference: to a configured source, within its allowlist - written by those who may create or update a
	// variable, administrators only (specs/009)
	if _, err := s.material.CheckWrite("", params, nil); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	provider := ""
	if strings.HasPrefix(*body.Value, material.Prefix) {
		provider = providerReference
	}
	now := s.now()
	s.upsert(w, r, name, func() *state.Secret {
		return &state.Secret{Type: variableType, Provider: provider, Params: params, Comment: deref(body.Comment),
			Owner: c.Owner(), CreatedAt: now, UpdatedAt: now, Version: 1}
	}, func(next *state.Secret) {
		next.Type, next.Provider, next.Params = variableType, provider, params
		if body.Comment != nil {
			next.Comment = *body.Comment
		}
	})
}
