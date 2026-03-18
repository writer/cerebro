package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/vulndb"
)

func resolveVulnDBStateFile(cfg *app.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.VulnDBStateFile) == "" {
		return filepath.Join(".cerebro", "vulndb.db")
	}
	return strings.TrimSpace(cfg.VulnDBStateFile)
}

func openVulnDBService(cfg *app.Config) (*vulndb.Service, io.Closer, error) {
	store, err := vulndb.NewSQLiteStore(resolveVulnDBStateFile(cfg))
	if err != nil {
		return nil, nil, err
	}
	return vulndb.NewService(store), store, nil
}

func buildFilesystemAnalyzer(cfg *app.Config, trivyBinary, gitleaksBinary, clamavBinary string) (*filesystemanalyzer.Analyzer, io.Closer, error) {
	vulnService, closer, err := openVulnDBService(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("open vulnerability db: %w", err)
	}
	var secretScanner filesystemanalyzer.SecretScanner
	var malwareScanner filesystemanalyzer.MalwareScanner
	if strings.TrimSpace(gitleaksBinary) != "" {
		secretScanner = filesystemanalyzer.NewGitleaksScanner(strings.TrimSpace(gitleaksBinary))
	}
	if strings.TrimSpace(clamavBinary) != "" {
		engine := scanner.NewMalwareScanner()
		engine.RegisterEngine(scanner.NewClamAVBinaryEngine(strings.TrimSpace(clamavBinary)))
		malwareScanner = engine
	}
	return filesystemanalyzer.New(filesystemanalyzer.Options{
		VulnerabilityScanner: scanner.NewTrivyFilesystemScanner(strings.TrimSpace(trivyBinary)),
		VulnerabilityMatcher: vulnService,
		SecretScanner:        secretScanner,
		MalwareScanner:       malwareScanner,
	}), closer, nil
}
