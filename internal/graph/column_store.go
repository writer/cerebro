package graph

import "strings"

type columnPresenceBitmap struct {
	words []uint64
}

func (b *columnPresenceBitmap) set(ordinal NodeOrdinal) {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok {
		return
	}
	if len(b.words) <= word {
		b.words = growUint64Column(b.words, word)
	}
	b.words[word] |= mask
}

func (b *columnPresenceBitmap) clear(ordinal NodeOrdinal) {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok || word >= len(b.words) {
		return
	}
	b.words[word] &^= mask
}

func (b columnPresenceBitmap) has(ordinal NodeOrdinal) bool {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok || word >= len(b.words) {
		return false
	}
	return b.words[word]&mask != 0
}

func (b columnPresenceBitmap) clone() columnPresenceBitmap {
	return columnPresenceBitmap{words: append([]uint64(nil), b.words...)}
}

type stringColumn struct {
	values   []string
	presence columnPresenceBitmap
}

func (c *stringColumn) set(ordinal NodeOrdinal, value string) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if len(c.values) <= index {
		c.values = growStringColumn(c.values, index)
	}
	c.values[index] = value
	c.presence.set(ordinal)
}

func (c *stringColumn) get(ordinal NodeOrdinal) (string, bool) {
	if ordinal == InvalidNodeOrdinal || !c.presence.has(ordinal) {
		return "", false
	}
	index := int(ordinal)
	if index >= len(c.values) {
		return "", false
	}
	return c.values[index], true
}

func (c *stringColumn) clear(ordinal NodeOrdinal) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if index < len(c.values) {
		c.values[index] = ""
	}
	c.presence.clear(ordinal)
}

func (c *stringColumn) clone() *stringColumn {
	if c == nil {
		return nil
	}
	return &stringColumn{
		values:   append([]string(nil), c.values...),
		presence: c.presence.clone(),
	}
}

type int64Column struct {
	values   []int64
	presence columnPresenceBitmap
}

func (c *int64Column) set(ordinal NodeOrdinal, value int64) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if len(c.values) <= index {
		c.values = growInt64Column(c.values, index)
	}
	c.values[index] = value
	c.presence.set(ordinal)
}

func (c *int64Column) get(ordinal NodeOrdinal) (int64, bool) {
	if ordinal == InvalidNodeOrdinal || !c.presence.has(ordinal) {
		return 0, false
	}
	index := int(ordinal)
	if index >= len(c.values) {
		return 0, false
	}
	return c.values[index], true
}

func (c *int64Column) clear(ordinal NodeOrdinal) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if index < len(c.values) {
		c.values[index] = 0
	}
	c.presence.clear(ordinal)
}

func (c *int64Column) clone() *int64Column {
	if c == nil {
		return nil
	}
	return &int64Column{
		values:   append([]int64(nil), c.values...),
		presence: c.presence.clone(),
	}
}

type float64Column struct {
	values   []float64
	presence columnPresenceBitmap
}

func (c *float64Column) set(ordinal NodeOrdinal, value float64) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if len(c.values) <= index {
		c.values = growFloat64Column(c.values, index)
	}
	c.values[index] = value
	c.presence.set(ordinal)
}

func (c *float64Column) get(ordinal NodeOrdinal) (float64, bool) {
	if ordinal == InvalidNodeOrdinal || !c.presence.has(ordinal) {
		return 0, false
	}
	index := int(ordinal)
	if index >= len(c.values) {
		return 0, false
	}
	return c.values[index], true
}

func (c *float64Column) clear(ordinal NodeOrdinal) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if index < len(c.values) {
		c.values[index] = 0
	}
	c.presence.clear(ordinal)
}

func (c *float64Column) clone() *float64Column {
	if c == nil {
		return nil
	}
	return &float64Column{
		values:   append([]float64(nil), c.values...),
		presence: c.presence.clone(),
	}
}

type boolColumn struct {
	values   []bool
	presence columnPresenceBitmap
}

func (c *boolColumn) set(ordinal NodeOrdinal, value bool) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if len(c.values) <= index {
		c.values = growBoolColumn(c.values, index)
	}
	c.values[index] = value
	c.presence.set(ordinal)
}

func (c *boolColumn) get(ordinal NodeOrdinal) (bool, bool) {
	if ordinal == InvalidNodeOrdinal || !c.presence.has(ordinal) {
		return false, false
	}
	index := int(ordinal)
	if index >= len(c.values) {
		return false, false
	}
	return c.values[index], true
}

func (c *boolColumn) clear(ordinal NodeOrdinal) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if index < len(c.values) {
		c.values[index] = false
	}
	c.presence.clear(ordinal)
}

func (c *boolColumn) clone() *boolColumn {
	if c == nil {
		return nil
	}
	return &boolColumn{
		values:   append([]bool(nil), c.values...),
		presence: c.presence.clone(),
	}
}

type stringSliceColumn struct {
	values   [][]string
	presence columnPresenceBitmap
}

func (c *stringSliceColumn) set(ordinal NodeOrdinal, value []string) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if len(c.values) <= index {
		c.values = growStringSliceColumn(c.values, index)
	}
	c.values[index] = append([]string(nil), value...)
	c.presence.set(ordinal)
}

func (c *stringSliceColumn) get(ordinal NodeOrdinal) ([]string, bool) {
	if ordinal == InvalidNodeOrdinal || !c.presence.has(ordinal) {
		return nil, false
	}
	index := int(ordinal)
	if index >= len(c.values) {
		return nil, false
	}
	return append([]string(nil), c.values[index]...), true
}

func (c *stringSliceColumn) clear(ordinal NodeOrdinal) {
	if ordinal == InvalidNodeOrdinal {
		return
	}
	index := int(ordinal)
	if index < len(c.values) {
		c.values[index] = nil
	}
	c.presence.clear(ordinal)
}

func (c *stringSliceColumn) clone() *stringSliceColumn {
	if c == nil {
		return nil
	}
	cloned := make([][]string, len(c.values))
	for i, value := range c.values {
		cloned[i] = append([]string(nil), value...)
	}
	return &stringSliceColumn{
		values:   cloned,
		presence: c.presence.clone(),
	}
}

// ColumnStore keeps promoted node properties in typed dense arrays keyed by
// property name and node ordinal.
type ColumnStore struct {
	strings      map[string]*stringColumn
	int64s       map[string]*int64Column
	float64s     map[string]*float64Column
	bools        map[string]*boolColumn
	stringSlices map[string]*stringSliceColumn
}

func NewColumnStore() *ColumnStore {
	return &ColumnStore{
		strings:      make(map[string]*stringColumn),
		int64s:       make(map[string]*int64Column),
		float64s:     make(map[string]*float64Column),
		bools:        make(map[string]*boolColumn),
		stringSlices: make(map[string]*stringSliceColumn),
	}
}

func (s *ColumnStore) Clone() *ColumnStore {
	if s == nil {
		return nil
	}
	cloned := NewColumnStore()
	for key, column := range s.strings {
		cloned.strings[key] = column.clone()
	}
	for key, column := range s.int64s {
		cloned.int64s[key] = column.clone()
	}
	for key, column := range s.float64s {
		cloned.float64s[key] = column.clone()
	}
	for key, column := range s.bools {
		cloned.bools[key] = column.clone()
	}
	for key, column := range s.stringSlices {
		cloned.stringSlices[key] = column.clone()
	}
	return cloned
}

func (s *ColumnStore) SetString(key string, ordinal NodeOrdinal, value string) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	column := s.strings[key]
	if column == nil {
		column = &stringColumn{}
		s.strings[key] = column
	}
	column.set(ordinal, value)
}

func (s *ColumnStore) String(key string, ordinal NodeOrdinal) (string, bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return "", false
	}
	column := s.strings[key]
	if column == nil {
		return "", false
	}
	return column.get(ordinal)
}

func (s *ColumnStore) ClearString(key string, ordinal NodeOrdinal) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	if column := s.strings[key]; column != nil {
		column.clear(ordinal)
	}
}

func (s *ColumnStore) SetInt64(key string, ordinal NodeOrdinal, value int64) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	column := s.int64s[key]
	if column == nil {
		column = &int64Column{}
		s.int64s[key] = column
	}
	column.set(ordinal, value)
}

func (s *ColumnStore) Int64(key string, ordinal NodeOrdinal) (int64, bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return 0, false
	}
	column := s.int64s[key]
	if column == nil {
		return 0, false
	}
	return column.get(ordinal)
}

func (s *ColumnStore) ClearInt64(key string, ordinal NodeOrdinal) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	if column := s.int64s[key]; column != nil {
		column.clear(ordinal)
	}
}

func (s *ColumnStore) SetFloat64(key string, ordinal NodeOrdinal, value float64) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	column := s.float64s[key]
	if column == nil {
		column = &float64Column{}
		s.float64s[key] = column
	}
	column.set(ordinal, value)
}

func (s *ColumnStore) Float64(key string, ordinal NodeOrdinal) (float64, bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return 0, false
	}
	column := s.float64s[key]
	if column == nil {
		return 0, false
	}
	return column.get(ordinal)
}

func (s *ColumnStore) ClearFloat64(key string, ordinal NodeOrdinal) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	if column := s.float64s[key]; column != nil {
		column.clear(ordinal)
	}
}

func (s *ColumnStore) SetBool(key string, ordinal NodeOrdinal, value bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	column := s.bools[key]
	if column == nil {
		column = &boolColumn{}
		s.bools[key] = column
	}
	column.set(ordinal, value)
}

func (s *ColumnStore) Bool(key string, ordinal NodeOrdinal) (bool, bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return false, false
	}
	column := s.bools[key]
	if column == nil {
		return false, false
	}
	return column.get(ordinal)
}

func (s *ColumnStore) ClearBool(key string, ordinal NodeOrdinal) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	if column := s.bools[key]; column != nil {
		column.clear(ordinal)
	}
}

func (s *ColumnStore) SetStringSlice(key string, ordinal NodeOrdinal, value []string) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	column := s.stringSlices[key]
	if column == nil {
		column = &stringSliceColumn{}
		s.stringSlices[key] = column
	}
	column.set(ordinal, value)
}

func (s *ColumnStore) StringSlice(key string, ordinal NodeOrdinal) ([]string, bool) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return nil, false
	}
	column := s.stringSlices[key]
	if column == nil {
		return nil, false
	}
	return column.get(ordinal)
}

func (s *ColumnStore) ClearStringSlice(key string, ordinal NodeOrdinal) {
	key = strings.TrimSpace(key)
	if s == nil || key == "" {
		return
	}
	if column := s.stringSlices[key]; column != nil {
		column.clear(ordinal)
	}
}

func (s *ColumnStore) ClearOrdinal(ordinal NodeOrdinal) {
	if s == nil || ordinal == InvalidNodeOrdinal {
		return
	}
	for _, column := range s.strings {
		column.clear(ordinal)
	}
	for _, column := range s.int64s {
		column.clear(ordinal)
	}
	for _, column := range s.float64s {
		column.clear(ordinal)
	}
	for _, column := range s.bools {
		column.clear(ordinal)
	}
	for _, column := range s.stringSlices {
		column.clear(ordinal)
	}
}

func growUint64Column(values []uint64, index int) []uint64 {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([]uint64, size)
	copy(grown, values)
	return grown
}

func growStringColumn(values []string, index int) []string {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([]string, size)
	copy(grown, values)
	return grown
}

func growInt64Column(values []int64, index int) []int64 {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([]int64, size)
	copy(grown, values)
	return grown
}

func growFloat64Column(values []float64, index int) []float64 {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([]float64, size)
	copy(grown, values)
	return grown
}

func growBoolColumn(values []bool, index int) []bool {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([]bool, size)
	copy(grown, values)
	return grown
}

func growStringSliceColumn(values [][]string, index int) [][]string {
	if index < len(values) {
		return values
	}
	size := len(values)
	if size == 0 {
		size = 1
	}
	for size <= index {
		size *= 2
	}
	grown := make([][]string, size)
	copy(grown, values)
	return grown
}
