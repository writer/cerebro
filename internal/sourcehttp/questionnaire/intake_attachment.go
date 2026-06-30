package questionnaire

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/writer/cerebro/internal/ports"
)

const maxIntakeAttachmentBytes = 12 << 20
const maxIntakeArchiveEntryBytes = maxIntakeAttachmentBytes

type xlsxWorksheet struct {
	Rows []xlsxRow `xml:"sheetData>row"`
}

type xlsxRow struct {
	Cells []xlsxCell `xml:"c"`
}

type xlsxCell struct {
	Ref       string `xml:"r,attr"`
	Type      string `xml:"t,attr"`
	Value     string `xml:"v"`
	InlineStr struct {
		Text string `xml:"t"`
	} `xml:"is"`
}

func createRunAttributes(request createRequest, questionCount int) map[string]string {
	attributes := map[string]string{}
	for key, value := range request.Attributes {
		if key = strings.TrimSpace(key); key != "" {
			attributes[key] = strings.TrimSpace(value)
		}
	}
	format := canonicalIntakeFormat(firstNonEmpty(request.IntakeFormat, request.SourceFormat, inferAttachmentFormat(request.SourceFilename, request.IntakeMimeType)))
	if format != "" {
		attributes["intake_format"] = format
	}
	if strings.TrimSpace(request.IntakeFile) != "" {
		attributes["intake_file_attached"] = "true"
		if contentType := strings.TrimSpace(request.IntakeMimeType); contentType != "" {
			attributes["intake_content_type"] = contentType
		}
	}
	if portalURL := strings.TrimSpace(request.PortalURL); portalURL != "" {
		attributes["portal_url"] = portalURL
		if _, ok := attributes["portal_status"]; !ok {
			attributes["portal_status"] = "questions_captured"
			if questionCount == 0 {
				attributes["portal_status"] = "needs_capture"
			}
		}
	}
	if notes := strings.TrimSpace(request.PortalNotes); notes != "" {
		attributes["portal_instructions"] = notes
	}
	return attributes
}

func parseIntakeAttachment(request createRequest) ([]ports.QuestionnaireQuestion, error) {
	data, err := decodeIntakeAttachment(request.IntakeFile)
	if err != nil {
		return nil, err
	}
	format := canonicalIntakeFormat(firstNonEmpty(request.IntakeFormat, request.SourceFormat, inferAttachmentFormat(request.SourceFilename, request.IntakeMimeType)))
	switch format {
	case "pdf":
		text, err := extractPDFText(data)
		if err != nil {
			return nil, err
		}
		return parsePDFPromptText(text)
	case "xlsx", "xlsm":
		rows, err := extractXLSXRows(data)
		if err != nil {
			return nil, err
		}
		questions, err := questionsFromSpreadsheetRows(rows)
		if err != nil {
			return nil, err
		}
		return questions, nil
	case "json", "csv", "tsv", "text", "portal":
		return parseIntakeText(string(data), format)
	default:
		return nil, fmt.Errorf("%w: intake attachment must be pdf, xlsx, csv, tsv, json, portal, or text", ErrInvalidRequest)
	}
}

func decodeIntakeAttachment(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if comma := strings.Index(value, ","); comma >= 0 && strings.HasPrefix(strings.ToLower(value[:comma+1]), "data:") {
		value = value[comma+1:]
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: intake_file_base64 is not valid base64", ErrInvalidRequest)
	}
	if len(data) > maxIntakeAttachmentBytes {
		return nil, fmt.Errorf("%w: intake attachment must be 12 MB or smaller", ErrInvalidRequest)
	}
	return data, nil
}

func canonicalIntakeFormat(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	format = strings.TrimPrefix(format, ".")
	switch format {
	case "application/pdf":
		return "pdf"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return "xlsx"
	case "application/vnd.ms-excel.sheet.macroenabled.12":
		return "xlsm"
	case "text/csv":
		return "csv"
	case "text/tab-separated-values":
		return "tsv"
	case "application/json":
		return "json"
	case "text/plain", "plain", "txt":
		return "text"
	default:
		return format
	}
}

func inferAttachmentFormat(filename string, contentType string) string {
	if contentType = strings.TrimSpace(contentType); contentType != "" {
		format := canonicalIntakeFormat(contentType)
		if format != "" && format != contentType {
			return format
		}
		if !strings.Contains(contentType, "/") && format != "" {
			return format
		}
	}
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(filename))) {
	case ".pdf":
		return "pdf"
	case ".xlsx":
		return "xlsx"
	case ".xlsm":
		return "xlsm"
	case ".csv":
		return "csv"
	case ".tsv":
		return "tsv"
	case ".json":
		return "json"
	case ".txt":
		return "text"
	default:
		return ""
	}
}

func extractXLSXRows(data []byte) ([][]string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: read xlsx workbook: %w", ErrInvalidRequest, err)
	}
	files := map[string]*zip.File{}
	worksheetNames := []string{}
	for _, file := range reader.File {
		files[file.Name] = file
		if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			worksheetNames = append(worksheetNames, file.Name)
		}
	}
	sort.Strings(worksheetNames)
	sharedStrings, err := readXLSXSharedStrings(files["xl/sharedStrings.xml"])
	if err != nil {
		return nil, err
	}
	allRows := [][]string{}
	for _, name := range worksheetNames {
		rows, err := readXLSXWorksheet(files[name], sharedStrings)
		if err != nil {
			return nil, err
		}
		allRows = append(allRows, rows...)
	}
	if len(allRows) == 0 {
		return nil, fmt.Errorf("%w: xlsx workbook did not contain worksheet rows", ErrInvalidRequest)
	}
	return allRows, nil
}

func readXLSXSharedStrings(file *zip.File) ([]string, error) {
	if file == nil {
		return nil, nil
	}
	body, err := readZipFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w: read xlsx shared strings: %w", ErrInvalidRequest, err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	values := []string{}
	inString := false
	var builder strings.Builder
	for {
		token, err := decoder.Token()
		if errorsIsEOF(err) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: parse xlsx shared strings: %w", ErrInvalidRequest, err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Local == "si" {
				inString = true
				builder.Reset()
			}
		case xml.EndElement:
			if token.Name.Local == "si" && inString {
				values = append(values, builder.String())
				inString = false
			}
		case xml.CharData:
			if inString {
				builder.WriteString(string(token))
			}
		}
	}
	return values, nil
}

func readXLSXWorksheet(file *zip.File, sharedStrings []string) ([][]string, error) {
	if file == nil {
		return nil, nil
	}
	body, err := readZipFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w: read xlsx worksheet: %w", ErrInvalidRequest, err)
	}
	var worksheet xlsxWorksheet
	if err := xml.Unmarshal(body, &worksheet); err != nil {
		return nil, fmt.Errorf("%w: parse xlsx worksheet: %w", ErrInvalidRequest, err)
	}
	rows := make([][]string, 0, len(worksheet.Rows))
	for _, row := range worksheet.Rows {
		cells := []string{}
		nextIndex := 0
		for _, cell := range row.Cells {
			index := xlsxColumnIndex(cell.Ref)
			if index < 0 {
				index = nextIndex
			}
			for len(cells) <= index {
				cells = append(cells, "")
			}
			cells[index] = xlsxCellValue(cell, sharedStrings)
			nextIndex = index + 1
		}
		cells = trimEmptyTail(cells)
		if len(cells) > 0 {
			rows = append(rows, cells)
		}
	}
	return rows, nil
}

func questionsFromSpreadsheetRows(rows [][]string) ([]ports.QuestionnaireQuestion, error) {
	for index, row := range rows {
		header := normalizedHeaders(row)
		questionIndex := headerIndex(header, "question", "question_text", "prompt")
		if questionIndex < 0 {
			continue
		}
		intakeRows := []intakeRow{}
		for _, record := range rows[index+1:] {
			if questionIndex >= len(record) || strings.TrimSpace(record[questionIndex]) == "" {
				continue
			}
			intakeRows = append(intakeRows, intakeRow{
				ID:                   columnValue(record, header, "id", "question_id"),
				Question:             record[questionIndex],
				Section:              columnValue(record, header, "section", "category"),
				RequiredAnswerFormat: columnValue(record, header, "required_answer_format", "answer_format", "format"),
				MappedControls:       splitList(columnValue(record, header, "mapped_controls", "controls", "control_ids")),
				RequiredSlots:        splitList(columnValue(record, header, "required_evidence_slots", "evidence_slots", "slots")),
				OwnerID:              columnValue(record, header, "owner_id", "owner", "assignee"),
			})
		}
		return questionsFromIntakeRows(intakeRows), nil
	}
	return nil, fmt.Errorf("%w: xlsx workbook must include a question, question_text, or prompt column", ErrInvalidRequest)
}

func xlsxCellValue(cell xlsxCell, sharedStrings []string) string {
	switch cell.Type {
	case "s":
		index, err := strconv.Atoi(strings.TrimSpace(cell.Value))
		if err == nil && index >= 0 && index < len(sharedStrings) {
			return strings.TrimSpace(sharedStrings[index])
		}
	case "inlineStr":
		return strings.TrimSpace(cell.InlineStr.Text)
	}
	return strings.TrimSpace(cell.Value)
}

func xlsxColumnIndex(ref string) int {
	if ref == "" {
		return -1
	}
	index := 0
	found := false
	for _, char := range ref {
		if char < 'A' || char > 'Z' {
			if char >= 'a' && char <= 'z' {
				char -= 'a' - 'A'
			} else {
				break
			}
		}
		found = true
		index = index*26 + int(char-'A'+1)
	}
	if !found {
		return -1
	}
	return index - 1
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(io.LimitReader(reader, maxIntakeArchiveEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxIntakeArchiveEntryBytes {
		return nil, fmt.Errorf("xlsx entry exceeds %d bytes", maxIntakeArchiveEntryBytes)
	}
	return body, nil
}

func trimEmptyTail(values []string) []string {
	for len(values) > 0 && strings.TrimSpace(values[len(values)-1]) == "" {
		values = values[:len(values)-1]
	}
	return values
}

func extractPDFText(data []byte) (string, error) {
	if !bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF")) {
		return "", fmt.Errorf("%w: pdf intake is not a PDF document", ErrInvalidRequest)
	}
	var text strings.Builder
	offset := 0
	for {
		streamIndex := bytes.Index(data[offset:], []byte("stream"))
		if streamIndex < 0 {
			break
		}
		streamIndex += offset
		bodyStart := streamIndex + len("stream")
		if bodyStart < len(data) && data[bodyStart] == '\r' {
			bodyStart++
		}
		if bodyStart < len(data) && data[bodyStart] == '\n' {
			bodyStart++
		}
		endRelative := bytes.Index(data[bodyStart:], []byte("endstream"))
		if endRelative < 0 {
			break
		}
		bodyEnd := bodyStart + endRelative
		raw := bytes.Trim(data[bodyStart:bodyEnd], "\r\n")
		dict := pdfStreamDictionary(data[:streamIndex])
		decoded := decodePDFStream(raw, dict)
		for _, value := range pdfTextStrings(decoded) {
			if strings.TrimSpace(value) != "" {
				text.WriteString(value)
				text.WriteByte('\n')
			}
		}
		offset = bodyEnd + len("endstream")
	}
	result := strings.TrimSpace(text.String())
	if result == "" {
		return "", fmt.Errorf("%w: pdf intake did not contain extractable text", ErrInvalidRequest)
	}
	return result, nil
}

func parsePDFPromptText(value string) ([]ports.QuestionnaireQuestion, error) {
	rows := []intakeRow{}
	for _, line := range strings.Split(value, "\n") {
		line = normalizePortalQuestionLine(line)
		if line == "" || !looksLikeQuestionnairePrompt(line) {
			continue
		}
		rows = append(rows, intakeRow{Question: line})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: pdf intake did not contain extractable questionnaire prompts", ErrInvalidRequest)
	}
	return questionsFromIntakeRows(rows), nil
}

func pdfStreamDictionary(prefix []byte) []byte {
	end := bytes.LastIndex(prefix, []byte(">>"))
	start := bytes.LastIndex(prefix, []byte("<<"))
	if start >= 0 && end >= start {
		return prefix[start : end+len(">>")]
	}
	return nil
}

func decodePDFStream(raw []byte, dict []byte) []byte {
	if !bytes.Contains(dict, []byte("/FlateDecode")) {
		return raw
	}
	reader, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	defer func() { _ = reader.Close() }()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxIntakeAttachmentBytes+1))
	if err != nil {
		return raw
	}
	if len(decoded) > maxIntakeAttachmentBytes {
		return raw
	}
	return decoded
}

func pdfTextStrings(data []byte) []string {
	values := []string{}
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '(':
			value, next := readPDFLiteralString(data, index+1)
			if next > index {
				values = append(values, value)
				index = next
			}
		case '<':
			if index+1 < len(data) && data[index+1] == '<' {
				continue
			}
			value, next := readPDFHexString(data, index+1)
			if next > index {
				values = append(values, value)
				index = next
			}
		}
	}
	return values
}

func readPDFLiteralString(data []byte, index int) (string, int) {
	var out []byte
	depth := 1
	for index < len(data) {
		char := data[index]
		index++
		if char == '\\' && index < len(data) {
			decoded, next := decodePDFEscape(data, index)
			if decoded >= 0 && decoded <= 255 {
				out = append(out, byte(decoded))
			}
			index = next
			continue
		}
		switch char {
		case '(':
			depth++
			out = append(out, char)
		case ')':
			depth--
			if depth == 0 {
				return decodePDFTextBytes(out), index - 1
			}
			out = append(out, char)
		default:
			out = append(out, char)
		}
	}
	return "", -1
}

func decodePDFEscape(data []byte, index int) (int, int) {
	char := data[index]
	switch char {
	case 'n':
		return '\n', index + 1
	case 'r':
		return '\r', index + 1
	case 't':
		return '\t', index + 1
	case 'b':
		return '\b', index + 1
	case 'f':
		return '\f', index + 1
	case '(', ')', '\\':
		return int(char), index + 1
	case '\r', '\n':
		for index < len(data) && (data[index] == '\r' || data[index] == '\n') {
			index++
		}
		return -1, index
	default:
		if char >= '0' && char <= '7' {
			end := index
			for end < len(data) && end-index < 3 && data[end] >= '0' && data[end] <= '7' {
				end++
			}
			value, err := strconv.ParseInt(string(data[index:end]), 8, 16)
			if err == nil {
				return int(value), end
			}
		}
		return int(char), index + 1
	}
}

func readPDFHexString(data []byte, index int) (string, int) {
	var hexText strings.Builder
	for index < len(data) {
		char := data[index]
		index++
		if char == '>' {
			text := hexText.String()
			if len(text)%2 == 1 {
				text += "0"
			}
			decoded, err := hex.DecodeString(text)
			if err != nil {
				return "", -1
			}
			return decodePDFTextBytes(decoded), index - 1
		}
		if unicode.IsSpace(rune(char)) {
			continue
		}
		hexText.WriteByte(char)
	}
	return "", -1
}

func decodePDFTextBytes(data []byte) string {
	if len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff {
		words := make([]uint16, 0, (len(data)-2)/2)
		for index := 2; index+1 < len(data); index += 2 {
			words = append(words, uint16(data[index])<<8|uint16(data[index+1]))
		}
		return string(utf16.Decode(words))
	}
	return strings.TrimSpace(string(data))
}

func normalizePortalQuestionLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "- ")
	line = strings.TrimPrefix(line, "* ")
	line = strings.TrimSpace(trimNumberedPrefix(line))
	lower := strings.ToLower(line)
	for _, prefix := range []string{"question:", "field:", "prompt:"} {
		if strings.HasPrefix(lower, prefix) {
			line = strings.TrimSpace(line[len(prefix):])
			lower = strings.ToLower(line)
		}
	}
	if strings.HasPrefix(lower, "question ") {
		if colon := strings.Index(line, ":"); colon > 0 && colon < 24 {
			line = strings.TrimSpace(line[colon+1:])
			lower = strings.ToLower(line)
		}
	}
	switch strings.Trim(lower, " .:") {
	case "", "next", "previous", "submit", "save", "cancel", "continue", "back", "log in", "login", "sign in", "upload", "upload file":
		return ""
	}
	return line
}

func looksLikeQuestionnairePrompt(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if strings.Contains(line, "?") {
		return true
	}
	lower := strings.ToLower(line)
	for _, prefix := range []string{
		"attach ",
		"confirm ",
		"describe ",
		"enter ",
		"explain ",
		"identify ",
		"list ",
		"provide ",
		"select ",
		"share ",
		"state ",
		"upload ",
	} {
		if strings.HasPrefix(lower, prefix) || strings.HasPrefix(lower, "please "+prefix) {
			return true
		}
	}
	return false
}

func trimNumberedPrefix(line string) string {
	index := 0
	for index < len(line) {
		char := rune(line[index])
		if unicode.IsDigit(char) || char == '.' || char == ')' {
			index++
			continue
		}
		break
	}
	if index > 0 && index < len(line) && unicode.IsSpace(rune(line[index])) {
		return strings.TrimSpace(line[index:])
	}
	return line
}

func errorsIsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
