package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/scanner"
)

type localScanDataset struct {
	Tables map[string][]map[string]interface{}
	Source string
}

type scanPreflightResult struct {
	Ready              bool   `json:"ready"`
	Mode               string `json:"mode"`
	Message            string `json:"message"`
	WarehouseConnected bool   `json:"warehouse_connected"`
	LocalDatasetLoaded bool   `json:"local_dataset_loaded"`
	LocalDatasetTables int    `json:"local_dataset_tables,omitempty"`
	LocalDatasetSource string `json:"local_dataset_source,omitempty"`
}

func resolveLocalScanDataset() (*localScanDataset, error) {
	fixturePath := strings.TrimSpace(scanLocalFixture)
	if fixturePath == "" {
		fixturePath = strings.TrimSpace(os.Getenv("CEREBRO_SCAN_FIXTURE"))
	}

	snapshotDir := strings.TrimSpace(scanSnapshotDir)
	if snapshotDir == "" {
		snapshotDir = strings.TrimSpace(os.Getenv("CEREBRO_SCAN_SNAPSHOT_DIR"))
	}

	if fixturePath == "" && snapshotDir == "" {
		return nil, nil
	}

	dataset := &localScanDataset{Tables: make(map[string][]map[string]interface{})}
	sources := make([]string, 0, 2)

	if fixturePath != "" {
		tables, err := loadLocalFixtureTables(fixturePath)
		if err != nil {
			return nil, err
		}
		mergeLocalTables(dataset.Tables, tables)
		sources = append(sources, fmt.Sprintf("fixture:%s", fixturePath))
	}

	if snapshotDir != "" {
		tables, err := loadSnapshotTables(snapshotDir)
		if err != nil {
			return nil, err
		}
		mergeLocalTables(dataset.Tables, tables)
		sources = append(sources, fmt.Sprintf("snapshot_dir:%s", snapshotDir))
	}

	if len(dataset.Tables) == 0 {
		return nil, fmt.Errorf("local scan dataset is empty: provide tables in --local-fixture or --snapshot-dir")
	}

	dataset.Source = strings.Join(sources, ", ")
	return dataset, nil
}

func loadLocalFixtureTables(path string) (map[string][]map[string]interface{}, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- path from CLI flag/env var, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read local fixture %q: %w", path, err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decode local fixture %q: %w", path, err)
	}

	if rawTables, ok := payload["tables"]; ok {
		tables, err := decodeTablesObject(rawTables)
		if err != nil {
			return nil, fmt.Errorf("decode fixture tables in %q: %w", path, err)
		}
		return tables, nil
	}

	tables, err := decodeTablesObject(data)
	if err != nil {
		return nil, fmt.Errorf("decode fixture table map in %q: %w", path, err)
	}
	return tables, nil
}

func loadSnapshotTables(dir string) (map[string][]map[string]interface{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot dir %q: %w", dir, err)
	}

	tables := make(map[string][]map[string]interface{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) // #nosec G304 G703 -- dir from CLI flag/env var, name from os.ReadDir entries
		if err != nil {
			return nil, fmt.Errorf("read snapshot file %q: %w", path, err)
		}

		assets, err := decodeAssetList(data)
		if err != nil {
			return nil, fmt.Errorf("decode snapshot file %q: %w", path, err)
		}

		table := normalizeTableName(strings.TrimSuffix(name, filepath.Ext(name)))
		if table == "" {
			continue
		}
		tables[table] = assets
	}

	return tables, nil
}

func decodeTablesObject(raw []byte) (map[string][]map[string]interface{}, error) {
	var tableRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tableRaw); err != nil {
		return nil, err
	}

	tables := make(map[string][]map[string]interface{}, len(tableRaw))
	for tableName, assetsRaw := range tableRaw {
		table := normalizeTableName(tableName)
		if table == "" {
			continue
		}

		assets, err := decodeAssetList(assetsRaw)
		if err != nil {
			return nil, fmt.Errorf("table %s: %w", table, err)
		}
		tables[table] = assets
	}

	return tables, nil
}

func decodeAssetList(raw []byte) ([]map[string]interface{}, error) {
	var assets []map[string]interface{}
	if err := json.Unmarshal(raw, &assets); err == nil {
		return assets, nil
	}

	var wrapper struct {
		Assets []map[string]interface{} `json:"assets"`
		Rows   []map[string]interface{} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}
	if len(wrapper.Assets) > 0 {
		return wrapper.Assets, nil
	}
	return wrapper.Rows, nil
}

func mergeLocalTables(dst, src map[string][]map[string]interface{}) {
	for table, assets := range src {
		normalized := normalizeTableName(table)
		if normalized == "" {
			continue
		}
		dst[normalized] = append(dst[normalized], assets...)
	}
}

func normalizeTableName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func sortedDatasetTables(dataset *localScanDataset) []string {
	if dataset == nil || len(dataset.Tables) == 0 {
		return nil
	}
	tables := make([]string, 0, len(dataset.Tables))
	for table := range dataset.Tables {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables
}

func evaluateScanPreflight(application *app.App, dataset *localScanDataset) scanPreflightResult {
	localTables := 0
	localSource := ""
	if dataset != nil {
		localTables = len(dataset.Tables)
		localSource = dataset.Source
	}

	result := scanPreflightResult{
		WarehouseConnected: application != nil && application.Warehouse != nil,
		LocalDatasetLoaded: localTables > 0,
		LocalDatasetTables: localTables,
		LocalDatasetSource: localSource,
	}

	if result.LocalDatasetLoaded {
		result.Ready = true
		result.Mode = "local-dataset"
		result.Message = fmt.Sprintf("ready: local dataset loaded with %d tables", result.LocalDatasetTables)
		return result
	}

	result.Mode = "warehouse"
	if result.WarehouseConnected {
		result.Ready = true
		result.Message = "ready: direct warehouse scan mode available"
		return result
	}

	result.Message = "warehouse not configured"
	return result
}

func runScanPreflight(application *app.App, dataset *localScanDataset) error {
	result := evaluateScanPreflight(application, dataset)

	if scanOutput == FormatJSON {
		if err := JSONOutput(result); err != nil {
			return err
		}
	} else {
		fmt.Println(bold("Scan Preflight"))
		fmt.Println(strings.Repeat("-", 40))
		fmt.Printf("Mode:                %s\n", result.Mode)
		fmt.Printf("Ready:               %t\n", result.Ready)
		fmt.Printf("Warehouse connected: %t\n", result.WarehouseConnected)
		fmt.Printf("Local dataset:       %t\n", result.LocalDatasetLoaded)
		if result.LocalDatasetLoaded {
			fmt.Printf("  Tables:            %d\n", result.LocalDatasetTables)
			fmt.Printf("  Source:            %s\n", result.LocalDatasetSource)
		}
		fmt.Printf("Message:             %s\n", result.Message)
	}

	if !result.Ready {
		return fmt.Errorf("scan preflight failed: %s", result.Message)
	}
	return nil
}

func scanOneLocalTable(ctx context.Context, application *app.App, table string, assets []map[string]interface{}, limit int, toxicCombos, graphAvailable bool, tuning app.ScanTuning) (scanned, violations int64, findings []map[string]interface{}, profile scanner.TableScanProfile) {
	fmt.Printf("\n%s Scanning %s...\n", color(colorCyan, "→"), table)

	profile = scanner.TableScanProfile{Table: table}
	start := time.Now()

	tableCtx := ctx
	cancel := func() {}
	if tuning.TableTimeout > 0 {
		tableCtx, cancel = context.WithTimeout(ctx, tuning.TableTimeout)
	}
	defer cancel()
	defer func() {
		profile.Scanned = scanned
		profile.Violations = violations
		profile.Duration = time.Since(start)
		if errors.Is(tableCtx.Err(), context.DeadlineExceeded) {
			profile.TimedOut = true
		}
	}()

	if len(assets) == 0 {
		fmt.Printf("  No assets found\n")
		return 0, 0, nil, profile
	}

	if limit > 0 && len(assets) > limit {
		assets = assets[:limit]
	}

	cursorTime, cursorID := scanner.ExtractScanCursor(assets)

	result := application.Scanner.ScanAssets(tableCtx, assets)
	profile.Batches = 1
	profile.CacheSkipped = result.Skipped
	profile.ScanErrors = len(result.Errors)
	scanned = result.Scanned
	violations = result.Violations

	for _, f := range result.Findings {
		application.Findings.Upsert(tableCtx, f)
		findings = append(findings, policyFindingToMap(f, findingSourcePolicy, nil))
	}

	if toxicCombos && !graphAvailable {
		toxicFindings := application.Scanner.DetectToxicCombinations(tableCtx, assets)
		violations += int64(len(toxicFindings))
		for _, f := range toxicFindings {
			application.Findings.Upsert(tableCtx, f)
			findings = append(findings, policyFindingToMap(f, findingSourceToxicCombo, map[string]interface{}{
				"toxic_combo": true,
				"graph_based": false,
			}))
		}
	}

	if scanned > 0 {
		if application.ScanWatermarks != nil {
			if cursorTime.IsZero() {
				cursorTime = time.Now().UTC()
			}
			application.ScanWatermarks.SetWatermark(table, cursorTime, cursorID, scanned)
		}
		fmt.Printf("  Scanned: %d, Violations: %d (%s)\n", scanned, violations, time.Since(start).Round(time.Millisecond))
	}

	return scanned, violations, findings, profile
}
