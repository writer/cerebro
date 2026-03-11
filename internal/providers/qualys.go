package providers

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"
)

// QualysProvider syncs vulnerability data from Qualys
type QualysProvider struct {
	*BaseProvider
	username string
	password string
	platform string
	baseURL  string
	client   *http.Client
}

var qualysPlatformURLs = map[string]string{
	"US1": "https://qualysapi.qualys.com",
	"US2": "https://qualysapi.qg2.apps.qualys.com",
	"US3": "https://qualysapi.qg3.apps.qualys.com",
	"US4": "https://qualysapi.qg4.apps.qualys.com",
	"EU1": "https://qualysapi.qualys.eu",
	"EU2": "https://qualysapi.qg2.apps.qualys.eu",
	"IN1": "https://qualysapi.qg1.apps.qualys.in",
	"CA1": "https://qualysapi.qg1.apps.qualys.ca",
	"AE1": "https://qualysapi.qg1.apps.qualys.ae",
}

func NewQualysProvider() *QualysProvider {
	return &QualysProvider{
		BaseProvider: NewBaseProvider("qualys", ProviderTypeSaaS),
		platform:     "US1",
		client:       newProviderHTTPClient(120 * time.Second),
	}
}

func (q *QualysProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	if err := q.BaseProvider.Configure(ctx, config); err != nil {
		return err
	}

	q.username = q.GetConfigString("username")
	q.password = q.GetConfigString("password")
	if platform := q.GetConfigString("platform"); platform != "" {
		q.platform = platform
	}

	if url, ok := qualysPlatformURLs[q.platform]; ok {
		q.baseURL = url
	} else {
		q.baseURL = qualysPlatformURLs["US1"]
	}

	return nil
}

func (q *QualysProvider) Test(ctx context.Context) error {
	_, err := q.request(ctx, "/api/2.0/fo/asset/host/?action=list&truncation_limit=1")
	return err
}

func (q *QualysProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "qualys_hosts",
			Description: "Qualys discovered hosts/assets",
			Columns: []ColumnSchema{
				{Name: "id", Type: "integer", Required: true},
				{Name: "ip", Type: "string"},
				{Name: "tracking_method", Type: "string"},
				{Name: "dns", Type: "string"},
				{Name: "netbios", Type: "string"},
				{Name: "os", Type: "string"},
				{Name: "last_scan_datetime", Type: "timestamp"},
				{Name: "last_vm_scanned_date", Type: "timestamp"},
				{Name: "last_vm_auth_scanned_date", Type: "timestamp"},
			},
			PrimaryKey: []string{"id"},
		},
		{
			Name:        "qualys_host_detections",
			Description: "Qualys vulnerability detections on hosts",
			Columns: []ColumnSchema{
				{Name: "host_id", Type: "integer", Required: true},
				{Name: "qid", Type: "integer", Required: true},
				{Name: "type", Type: "string"},
				{Name: "severity", Type: "integer"},
				{Name: "status", Type: "string"},
				{Name: "first_found_datetime", Type: "timestamp"},
				{Name: "last_found_datetime", Type: "timestamp"},
				{Name: "times_found", Type: "integer"},
				{Name: "is_ignored", Type: "boolean"},
				{Name: "is_disabled", Type: "boolean"},
			},
			PrimaryKey: []string{"host_id", "qid"},
		},
		{
			Name:        "qualys_knowledge_base",
			Description: "Qualys vulnerability knowledge base",
			Columns: []ColumnSchema{
				{Name: "qid", Type: "integer", Required: true},
				{Name: "title", Type: "string"},
				{Name: "category", Type: "string"},
				{Name: "severity_level", Type: "integer"},
				{Name: "cve_list", Type: "array"},
				{Name: "solution", Type: "string"},
				{Name: "pci_flag", Type: "boolean"},
				{Name: "published_datetime", Type: "timestamp"},
			},
			PrimaryKey: []string{"qid"},
		},
	}
}

func (q *QualysProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{
		Provider:  q.Name(),
		StartedAt: start,
	}

	// Sync hosts
	hosts, err := q.syncHosts(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "hosts: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *hosts)
		result.TotalRows += hosts.Rows
	}

	// Sync detections
	detections, err := q.syncDetections(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "detections: "+err.Error())
	} else {
		result.Tables = append(result.Tables, *detections)
		result.TotalRows += detections.Rows
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(start)

	return result, nil
}

func (q *QualysProvider) request(ctx context.Context, path string) ([]byte, error) {
	url := q.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(q.username, q.password)
	req.Header.Set("X-Requested-With", "Cerebro")

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("qualys API error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (q *QualysProvider) syncHosts(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "qualys_hosts"}

	body, err := q.request(ctx, "/api/2.0/fo/asset/host/?action=list&truncation_limit=1000")
	if err != nil {
		return result, err
	}

	var response struct {
		XMLName xml.Name `xml:"HOST_LIST_OUTPUT"`
		Hosts   []struct {
			ID int `xml:"ID"`
		} `xml:"RESPONSE>HOST_LIST>HOST"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Hosts))
	result.Inserted = result.Rows
	return result, nil
}

func (q *QualysProvider) syncDetections(ctx context.Context) (*TableResult, error) {
	result := &TableResult{Name: "qualys_host_detections"}

	body, err := q.request(ctx, "/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=1000")
	if err != nil {
		return result, err
	}

	var response struct {
		XMLName    xml.Name `xml:"HOST_LIST_VM_DETECTION_OUTPUT"`
		Detections []struct {
			QID int `xml:"QID"`
		} `xml:"RESPONSE>HOST_LIST>HOST>DETECTION_LIST>DETECTION"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		return result, err
	}

	result.Rows = int64(len(response.Detections))
	result.Inserted = result.Rows
	return result, nil
}
