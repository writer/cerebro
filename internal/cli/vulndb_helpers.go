package cli

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/vulndb"
)

type nopCloser struct{}

func (nopCloser) Close() error {
	return nil
}

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

func buildFilesystemAnalyzer(cfg *app.Config, trivyBinary string) (*filesystemanalyzer.Analyzer, io.Closer, error) {
	vulnService, closer, err := openVulnDBService(cfg)
	if err != nil {
		return filesystemanalyzer.New(filesystemanalyzer.Options{
			VulnerabilityScanner: scanner.NewTrivyFilesystemScanner(strings.TrimSpace(trivyBinary)),
		}), nopCloser{}, nil
	}
	return filesystemanalyzer.New(filesystemanalyzer.Options{
		VulnerabilityScanner: scanner.NewTrivyFilesystemScanner(strings.TrimSpace(trivyBinary)),
		VulnerabilityMatcher: vulnService,
	}), closer, nil
}
