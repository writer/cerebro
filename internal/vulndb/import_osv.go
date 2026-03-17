package vulndb

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

var (
	maxOSVImportBytes  int64 = 256 << 20
	maxOSVImportRows         = 500_000
	maxEPSSImportBytes int64 = 256 << 20
	maxEPSSImportRows        = 1_000_000
	maxKEVImportBytes  int64 = 64 << 20
	maxKEVImportRows         = 250_000
)

type osvAdvisory struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Published        time.Time       `json:"published"`
	Modified         time.Time       `json:"modified"`
	Withdrawn        *time.Time      `json:"withdrawn"`
	Severity         []osvSeverity   `json:"severity"`
	References       []osvReference  `json:"references"`
	Affected         []osvAffected   `json:"affected"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

type ImportReport struct {
	Source      string `json:"source"`
	Imported    int    `json:"imported"`
	MatchedEPSS int64  `json:"matched_epss"`
	MatchedKEV  int64  `json:"matched_kev"`
}

func (s *Service) withWriteStore(ctx context.Context, fn func(advisoryWriteStore) (ImportReport, error)) (ImportReport, error) {
	writer := advisoryWriteStore(s.store)
	if txStore, ok := s.store.(transactionalWriteStore); ok {
		var report ImportReport
		err := txStore.WithWriteTx(ctx, func(txWriter advisoryWriteStore) error {
			var txErr error
			report, txErr = fn(txWriter)
			return txErr
		})
		return report, err
	}
	return fn(writer)
}

func (s *Service) ImportOSVJSON(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.withWriteStore(ctx, func(store advisoryWriteStore) (ImportReport, error) {
		limited := &io.LimitedReader{R: r, N: maxOSVImportBytes + 1}
		reader := bufio.NewReader(limited)
		first, err := firstNonSpaceByte(reader)
		if err != nil {
			return ImportReport{}, err
		}
		decoder := json.NewDecoder(reader)
		report := ImportReport{Source: strings.TrimSpace(source)}
		sizeLimitErr := func(err error) error {
			if limited.N <= 0 {
				return fmt.Errorf("osv feed exceeded maximum size %d bytes", maxOSVImportBytes)
			}
			return err
		}
		importOne := func(doc osvAdvisory) error {
			vuln, affected := normalizeOSVAdvisory(doc)
			if vuln.ID == "" {
				return nil
			}
			if err := store.UpsertAdvisory(ctx, vuln, affected); err != nil {
				return err
			}
			report.Imported++
			if report.Imported > maxOSVImportRows {
				return fmt.Errorf("osv feed exceeded maximum row count %d", maxOSVImportRows)
			}
			return nil
		}
		if first == '[' {
			tok, err := decoder.Token()
			if err != nil {
				return report, fmt.Errorf("read osv array start: %w", sizeLimitErr(err))
			}
			if _, ok := tok.(json.Delim); !ok {
				return report, fmt.Errorf("invalid osv array stream")
			}
			for decoder.More() {
				var doc osvAdvisory
				if err := decoder.Decode(&doc); err != nil {
					return report, fmt.Errorf("decode osv advisory: %w", sizeLimitErr(err))
				}
				if err := importOne(doc); err != nil {
					return report, fmt.Errorf("import osv advisory %s: %w", doc.ID, err)
				}
			}
			if _, err := decoder.Token(); err != nil {
				return report, fmt.Errorf("read osv array end: %w", sizeLimitErr(err))
			}
		} else {
			for {
				var doc osvAdvisory
				if err := decoder.Decode(&doc); err != nil {
					if err == io.EOF {
						break
					}
					return report, fmt.Errorf("decode osv advisory stream: %w", sizeLimitErr(err))
				}
				if err := importOne(doc); err != nil {
					return report, fmt.Errorf("import osv advisory %s: %w", doc.ID, err)
				}
			}
		}
		if limited.N <= 0 {
			return report, fmt.Errorf("osv feed exceeded maximum size %d bytes", maxOSVImportBytes)
		}
		attemptedAt := s.now().UTC()
		if err := store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: attemptedAt, LastSuccessAt: attemptedAt, RecordsSynced: report.Imported}); err != nil {
			return report, err
		}
		return report, nil
	})
}

func (s *Service) ImportKEVJSON(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.withWriteStore(ctx, func(store advisoryWriteStore) (ImportReport, error) {
		limited := &io.LimitedReader{R: r, N: maxKEVImportBytes + 1}
		decoder := json.NewDecoder(limited)
		report := ImportReport{Source: strings.TrimSpace(source)}
		sizeLimitErr := func(err error) error {
			if limited.N <= 0 {
				return fmt.Errorf("kev feed exceeded maximum size %d bytes", maxKEVImportBytes)
			}
			return err
		}
		type kevVulnerability struct {
			CVEID string `json:"cveID"`
		}
		flushBatch := func(cves []string) (int64, error) {
			if len(cves) == 0 {
				return 0, nil
			}
			return store.MarkKEV(ctx, cves)
		}

		token, err := decoder.Token()
		if err != nil {
			return ImportReport{}, fmt.Errorf("decode kev feed: %w", sizeLimitErr(err))
		}
		start, ok := token.(json.Delim)
		if !ok || start != '{' {
			return ImportReport{}, fmt.Errorf("decode kev feed: expected object start")
		}

		const kevBatchSize = 1024
		batch := make([]string, 0, kevBatchSize)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ImportReport{}, fmt.Errorf("decode kev feed key: %w", sizeLimitErr(err))
			}
			key, ok := keyToken.(string)
			if !ok {
				return ImportReport{}, fmt.Errorf("decode kev feed: invalid object key")
			}
			if key != "vulnerabilities" {
				var discard any
				if err := decoder.Decode(&discard); err != nil {
					return ImportReport{}, fmt.Errorf("decode kev feed field %q: %w", key, sizeLimitErr(err))
				}
				continue
			}
			arrayToken, err := decoder.Token()
			if err != nil {
				return ImportReport{}, fmt.Errorf("decode kev vulnerabilities start: %w", sizeLimitErr(err))
			}
			arrayStart, ok := arrayToken.(json.Delim)
			if !ok || arrayStart != '[' {
				return ImportReport{}, fmt.Errorf("decode kev feed: vulnerabilities must be an array")
			}
			for decoder.More() {
				var vuln kevVulnerability
				if err := decoder.Decode(&vuln); err != nil {
					return ImportReport{}, fmt.Errorf("decode kev vulnerability: %w", sizeLimitErr(err))
				}
				report.Imported++
				if report.Imported > maxKEVImportRows {
					return ImportReport{}, fmt.Errorf("kev feed exceeded maximum row count %d", maxKEVImportRows)
				}
				if cve := strings.TrimSpace(vuln.CVEID); cve != "" {
					batch = append(batch, cve)
				}
				if len(batch) >= kevBatchSize {
					matched, err := flushBatch(batch)
					if err != nil {
						return ImportReport{}, err
					}
					report.MatchedKEV += matched
					batch = batch[:0]
				}
			}
			endToken, err := decoder.Token()
			if err != nil {
				return ImportReport{}, fmt.Errorf("decode kev vulnerabilities end: %w", sizeLimitErr(err))
			}
			arrayEnd, ok := endToken.(json.Delim)
			if !ok || arrayEnd != ']' {
				return ImportReport{}, fmt.Errorf("decode kev feed: invalid vulnerabilities terminator")
			}
		}
		endToken, err := decoder.Token()
		if err != nil {
			return ImportReport{}, fmt.Errorf("decode kev feed end: %w", sizeLimitErr(err))
		}
		end, ok := endToken.(json.Delim)
		if !ok || end != '}' {
			return ImportReport{}, fmt.Errorf("decode kev feed: invalid object terminator")
		}
		matched, err := flushBatch(batch)
		if err != nil {
			return ImportReport{}, err
		}
		report.MatchedKEV += matched
		if limited.N <= 0 {
			return ImportReport{}, fmt.Errorf("kev feed exceeded maximum size %d bytes", maxKEVImportBytes)
		}
		now := s.now().UTC()
		if err := store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: now, LastSuccessAt: now, RecordsSynced: report.Imported}); err != nil {
			return report, err
		}
		return report, nil
	})
}

func (s *Service) ImportEPSSCSV(ctx context.Context, source string, r io.Reader) (ImportReport, error) {
	if s == nil || s.store == nil {
		return ImportReport{}, fmt.Errorf("vulnerability database service is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.withWriteStore(ctx, func(store advisoryWriteStore) (ImportReport, error) {
		limited := &io.LimitedReader{R: r, N: maxEPSSImportBytes + 1}
		reader := csv.NewReader(limited)
		reader.FieldsPerRecord = -1
		reader.Comment = '#'
		report := ImportReport{Source: strings.TrimSpace(source)}
		rowCount := 0
		for {
			record, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return ImportReport{}, fmt.Errorf("read epss csv: %w", err)
			}
			rowCount++
			if rowCount > maxEPSSImportRows {
				return report, fmt.Errorf("epss csv exceeded maximum row count %d", maxEPSSImportRows)
			}
			if len(record) < 3 {
				continue
			}
			if rowCount == 1 && strings.EqualFold(strings.TrimSpace(record[0]), "cve") {
				continue
			}
			score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
			if err != nil {
				continue
			}
			percentile, err := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
			if err != nil {
				continue
			}
			updated, err := store.UpsertEPSS(ctx, record[0], score, percentile)
			if err != nil {
				return report, err
			}
			report.Imported++
			report.MatchedEPSS += updated
		}
		if limited.N == 0 {
			return report, fmt.Errorf("epss csv exceeded maximum size %d bytes", maxEPSSImportBytes)
		}
		now := s.now().UTC()
		if err := store.UpdateSyncState(ctx, SyncState{Source: report.Source, LastAttemptAt: now, LastSuccessAt: now, RecordsSynced: report.Imported}); err != nil {
			return report, err
		}
		return report, nil
	})
}

func normalizeOSVAdvisory(doc osvAdvisory) (Vulnerability, []AffectedPackage) {
	vuln := Vulnerability{
		ID:          strings.TrimSpace(strings.ToUpper(doc.ID)),
		Aliases:     uniqueUpperStrings(doc.Aliases),
		Summary:     strings.TrimSpace(doc.Summary),
		Details:     strings.TrimSpace(doc.Details),
		PublishedAt: doc.Published,
		ModifiedAt:  doc.Modified,
		WithdrawnAt: doc.Withdrawn,
		Source:      "osv",
	}
	vuln.Severity, vuln.CVSS = extractOSVSeverity(doc)
	for _, ref := range doc.References {
		if strings.TrimSpace(ref.URL) != "" {
			vuln.References = append(vuln.References, strings.TrimSpace(ref.URL))
		}
	}
	affected := make([]AffectedPackage, 0)
	for _, pkg := range doc.Affected {
		ecosystem := normalizeEcosystem(pkg.Package.Ecosystem)
		packageName := strings.TrimSpace(strings.ToLower(pkg.Package.Name))
		if ecosystem == "" || packageName == "" {
			continue
		}
		for _, version := range uniqueStrings(pkg.Versions) {
			affected = append(affected, AffectedPackage{
				VulnerabilityID:   vuln.ID,
				Ecosystem:         ecosystem,
				PackageName:       packageName,
				RangeType:         "EXACT",
				VulnerableVersion: strings.TrimSpace(version),
			})
		}
		for _, item := range pkg.Ranges {
			currentIntroduced := ""
			rangeType := strings.TrimSpace(strings.ToUpper(item.Type))
			for _, event := range item.Events {
				if strings.TrimSpace(event.Introduced) != "" {
					currentIntroduced = strings.TrimSpace(event.Introduced)
					if currentIntroduced == "0" {
						currentIntroduced = ""
					}
				}
				if strings.TrimSpace(event.Fixed) != "" {
					affected = append(affected, AffectedPackage{
						VulnerabilityID: vuln.ID,
						Ecosystem:       ecosystem,
						PackageName:     packageName,
						RangeType:       rangeType,
						Introduced:      currentIntroduced,
						Fixed:           strings.TrimSpace(event.Fixed),
					})
					currentIntroduced = ""
					continue
				}
				if strings.TrimSpace(event.LastAffected) != "" {
					affected = append(affected, AffectedPackage{
						VulnerabilityID: vuln.ID,
						Ecosystem:       ecosystem,
						PackageName:     packageName,
						RangeType:       rangeType,
						Introduced:      currentIntroduced,
						LastAffected:    strings.TrimSpace(event.LastAffected),
					})
					currentIntroduced = ""
				}
			}
			if currentIntroduced != "" {
				affected = append(affected, AffectedPackage{
					VulnerabilityID: vuln.ID,
					Ecosystem:       ecosystem,
					PackageName:     packageName,
					RangeType:       rangeType,
					Introduced:      currentIntroduced,
				})
			}
		}
	}
	return vuln, affected
}

func extractOSVSeverity(doc osvAdvisory) (string, float64) {
	if len(doc.DatabaseSpecific) > 0 {
		var databaseSpecific map[string]any
		if err := json.Unmarshal(doc.DatabaseSpecific, &databaseSpecific); err == nil {
			if raw, ok := databaseSpecific["severity"].(string); ok {
				severity := normalizeSeverity(raw)
				if severity != "" {
					return severity, 0
				}
			}
		}
	}
	for _, sev := range doc.Severity {
		score, err := parseSeverityScore(strings.TrimSpace(sev.Score))
		if err == nil {
			return severityFromScore(score), score
		}
	}
	return "unknown", 0
}

func parseSeverityScore(raw string) (float64, error) {
	score, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err == nil {
		return score, nil
	}
	return parseCVSSVectorScore(raw)
}

func parseCVSSVectorScore(raw string) (float64, error) {
	vector := strings.TrimSpace(raw)
	if vector == "" {
		return 0, fmt.Errorf("empty cvss vector")
	}
	parts := strings.Split(vector, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("unsupported cvss vector %q", raw)
	}
	metrics := make(map[string]string, len(parts)-1)
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		metrics[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("missing scope metric")
	}
	av, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	if !ok {
		return 0, fmt.Errorf("missing attack vector metric")
	}
	ac, ok := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	if !ok {
		return 0, fmt.Errorf("missing attack complexity metric")
	}
	ui, ok := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	if !ok {
		return 0, fmt.Errorf("missing user interaction metric")
	}
	pr, ok := privilegeRequiredWeight(metrics["PR"], scope)
	if !ok {
		return 0, fmt.Errorf("missing privileges required metric")
	}
	conf, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["C"]]
	if !ok {
		return 0, fmt.Errorf("missing confidentiality metric")
	}
	integ, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["I"]]
	if !ok {
		return 0, fmt.Errorf("missing integrity metric")
	}
	avail, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["A"]]
	if !ok {
		return 0, fmt.Errorf("missing availability metric")
	}

	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * av * ac * pr * ui
	var scoreValue float64
	if scope == "U" {
		scoreValue = math.Min(impact+exploitability, 10)
	} else {
		scoreValue = math.Min(1.08*(impact+exploitability), 10)
	}
	return roundUpOneDecimal(scoreValue), nil
}

func privilegeRequiredWeight(raw, scope string) (float64, bool) {
	switch scope {
	case "C":
		value, ok := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[raw]
		return value, ok
	default:
		value, ok := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[raw]
		return value, ok
	}
}

func roundUpOneDecimal(value float64) float64 {
	return math.Ceil(value*10) / 10
}

func firstNonSpaceByte(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, fmt.Errorf("empty advisory stream")
			}
			return 0, err
		}
		if !strings.ContainsRune(" \n\r\t", rune(b)) {
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
}
