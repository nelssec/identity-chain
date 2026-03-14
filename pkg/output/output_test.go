package output

import (
	"bytes"
	"testing"
)

func TestNewWriter_Table(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, FormatTable)
	if _, ok := w.(*TableWriter); !ok {
		t.Errorf("NewWriter(FormatTable) returned %T, want *TableWriter", w)
	}
}

func TestNewWriter_JSON(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, FormatJSON)
	if _, ok := w.(*JSONWriter); !ok {
		t.Errorf("NewWriter(FormatJSON) returned %T, want *JSONWriter", w)
	}
}

func TestNewWriter_DOT(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, FormatDOT)
	if _, ok := w.(*DOTWriter); !ok {
		t.Errorf("NewWriter(FormatDOT) returned %T, want *DOTWriter", w)
	}
}

func TestNewWriter_UnknownDefaultsToTable(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, Format("yaml"))
	if _, ok := w.(*TableWriter); !ok {
		t.Errorf("NewWriter(unknown format) returned %T, want *TableWriter", w)
	}
}

func TestNewWriter_EmptyDefaultsToTable(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, Format(""))
	if _, ok := w.(*TableWriter); !ok {
		t.Errorf("NewWriter(empty) returned %T, want *TableWriter", w)
	}
}

func TestFormatConstants(t *testing.T) {
	if FormatTable != "table" {
		t.Errorf("FormatTable = %q, want %q", FormatTable, "table")
	}
	if FormatJSON != "json" {
		t.Errorf("FormatJSON = %q, want %q", FormatJSON, "json")
	}
	if FormatDOT != "dot" {
		t.Errorf("FormatDOT = %q, want %q", FormatDOT, "dot")
	}
}
