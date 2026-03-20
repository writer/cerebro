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
	if strings.TrimSpace(gitleaksBinary) != "" {
		secretScanner = filesystemanalyzer.NewGitleaksScanner(strings.TrimSpace(gitleaksBinary))
	}
	return filesystemanalyzer.New(filesystemanalyzer.Options{
		VulnerabilityScanner: scanner.NewTrivyFilesystemScanner(strings.TrimSpace(trivyBinary)),
		VulnerabilityMatcher: vulnService,
		SecretScanner:        secretScanner,
		MalwareScanner:       buildMalwareScanner(cfg, clamavBinary),
	}), closer, nil
}

func buildMalwareScanner(cfg *app.Config, clamavBinary string) filesystemanalyzer.MalwareScanner {
	malwareScanner := scanner.NewMalwareScanner()
	configured := false
	if strings.TrimSpace(clamavBinary) != "" {
		malwareScanner.RegisterEngine(scanner.NewClamAVBinaryEngine(strings.TrimSpace(clamavBinary)))
		configured = true
	}
	if cfg == nil {
		if !configured {
			return nil
		}
		return malwareScanner
	}
	if host := strings.TrimSpace(cfg.MalwareScanClamAVHost); host != "" && cfg.MalwareScanClamAVPort > 0 {
		malwareScanner.RegisterEngine(scanner.NewClamAVEngine(host, cfg.MalwareScanClamAVPort))
		configured = true
	}
	if apiKey := strings.TrimSpace(cfg.MalwareScanVirusTotalAPIKey); apiKey != "" {
		malwareScanner.RegisterEngine(scanner.NewVirusTotalEngine(apiKey))
		configured = true
	}
	if !configured {
		return nil
	}
	return malwareScanner
}
