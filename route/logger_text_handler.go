package route

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

type attrEntry struct {
	groups []string
	attr   slog.Attr
}

type stdTextHandler struct {
	w           io.Writer
	leveler     slog.Leveler
	replaceAttr func([]string, slog.Attr) slog.Attr
	attrs       []attrEntry
	groups      []string
	mu          *sync.Mutex
}

func newStdTextHandler(w io.Writer, opts *slog.HandlerOptions) *stdTextHandler {
	h := &stdTextHandler{
		w:       w,
		leveler: slog.LevelInfo,
		mu:      &sync.Mutex{},
	}
	if opts != nil {
		if opts.Level != nil {
			h.leveler = opts.Level
		}
		h.replaceAttr = opts.ReplaceAttr
	}
	return h
}

func (h *stdTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

func (h *stdTextHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.Enabled(ctx, r.Level) {
		return nil
	}
	var b strings.Builder
	timestamp := r.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	b.WriteString(timestamp.Local().Format("2006-01-02 15:04:05"))
	b.WriteByte(' ')
	b.WriteString(strings.ToUpper(r.Level.String()))
	if msg := strings.TrimSpace(r.Message); msg != "" {
		b.WriteByte(' ')
		b.WriteString(msg)
	}
	for _, entry := range h.attrs {
		h.writeAttr(&b, entry.groups, entry.attr)
	}
	r.Attrs(func(a slog.Attr) bool {
		h.processAttr(h.groups, a, func(gs []string, attr slog.Attr) {
			h.writeAttr(&b, gs, attr)
		})
		return true
	})
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *stdTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := h.clone()
	for _, attr := range attrs {
		nh.processAttr(nh.groups, attr, func(gs []string, a slog.Attr) {
			nh.attrs = append(nh.attrs, attrEntry{groups: copyGroups(gs), attr: a})
		})
	}
	return nh
}

func (h *stdTextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := h.clone()
	nh.groups = appendGroup(nh.groups, name)
	return nh
}

func (h *stdTextHandler) clone() *stdTextHandler {
	nh := &stdTextHandler{
		w:           h.w,
		leveler:     h.leveler,
		replaceAttr: h.replaceAttr,
		mu:          h.mu,
		groups:      copyGroups(h.groups),
	}
	if len(h.attrs) > 0 {
		nh.attrs = make([]attrEntry, len(h.attrs))
		for i, entry := range h.attrs {
			nh.attrs[i] = attrEntry{groups: copyGroups(entry.groups), attr: entry.attr}
		}
	}
	return nh
}

func (h *stdTextHandler) processAttr(groups []string, attr slog.Attr, fn func([]string, slog.Attr)) {
	attr.Value = attr.Value.Resolve()
	if h.replaceAttr != nil {
		attr = h.replaceAttr(groups, attr)
		if attr.Equal(slog.Attr{}) {
			return
		}
		attr.Value = attr.Value.Resolve()
	}
	if attr.Value.Kind() == slog.KindGroup {
		nextGroups := groups
		if attr.Key != "" {
			nextGroups = appendGroup(groups, attr.Key)
		}
		for _, child := range attr.Value.Group() {
			h.processAttr(nextGroups, child, fn)
		}
		return
	}
	fn(groups, attr)
}

func (h *stdTextHandler) writeAttr(b *strings.Builder, groups []string, attr slog.Attr) {
	if attr.Value.Kind() == slog.KindGroup {
		return
	}
	val := formatValue(attr.Value)
	if val == "" {
		return
	}
	b.WriteByte(' ')
	b.WriteString(val)
}

func appendGroup(groups []string, name string) []string {
	if name == "" {
		return groups
	}
	out := make([]string, len(groups)+1)
	copy(out, groups)
	out[len(groups)] = name
	return out
}

func copyGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	dup := make([]string, len(groups))
	copy(dup, groups)
	return dup
}

func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(v.Float64(), 'f', -1, 64)
	case slog.KindBool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindAny:
		return fmt.Sprint(v.Any())
	default:
		return v.String()
	}
}
