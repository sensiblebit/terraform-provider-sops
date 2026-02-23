package sops

import (
	"reflect"
	"testing"
)

func TestParsePath(t *testing.T) {
	tc := []struct {
		name     string
		input    string
		expected []interface{}
	}{
		{
			name:     "simple top-level key",
			input:    "hello",
			expected: []interface{}{"hello"},
		},
		{
			name:     "nested key",
			input:    "db.password",
			expected: []interface{}{"db", "password"},
		},
		{
			name:     "array index",
			input:    "list.0.name",
			expected: []interface{}{"list", 0, "name"},
		},
		{
			name:     "deeply nested",
			input:    "a.b.c.d.e",
			expected: []interface{}{"a", "b", "c", "d", "e"},
		},
		{
			name:     "numeric segment becomes int",
			input:    "items.42",
			expected: []interface{}{"items", 42},
		},
		{
			name:     "mixed nested and array",
			input:    "servers.0.config.port",
			expected: []interface{}{"servers", 0, "config", "port"},
		},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			result := parsePath(c.input)
			if !reflect.DeepEqual(result, c.expected) {
				t.Errorf("parsePath(%q) = %v, want %v", c.input, result, c.expected)
			}
		})
	}
}

func TestValidateKeyPath(t *testing.T) {
	tc := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid simple key", input: "hello", wantErr: false},
		{name: "valid nested key", input: "db.password", wantErr: false},
		{name: "valid array path", input: "list.0.name", wantErr: false},
		{name: "empty string", input: "", wantErr: true},
		{name: "leading dot", input: ".foo", wantErr: true},
		{name: "trailing dot", input: "foo.", wantErr: true},
		{name: "consecutive dots", input: "foo..bar", wantErr: true},
		{name: "just a dot", input: ".", wantErr: true},
		{name: "valid numeric key", input: "123", wantErr: false},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			err := validateKeyPath(c.input)
			if (err != nil) != c.wantErr {
				t.Errorf("validateKeyPath(%q) error = %v, wantErr %v", c.input, err, c.wantErr)
			}
		})
	}
}
