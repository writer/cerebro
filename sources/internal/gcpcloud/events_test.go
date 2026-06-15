package gcpcloud

import "testing"

func TestGCSObjectEventDoesNotDowngradeMetadataClassification(t *testing.T) {
	event, err := GCSObjectEvent(Settings{ProjectID: "writer-prod"}, GCSObjectRecord{
		ID:       "data/training.csv/1",
		Name:     "training.csv",
		Bucket:   "data",
		Metadata: map[string]string{"data_classification": "restricted"},
		ContentInspection: GCSObjectContentInspection{
			Inspected:          true,
			DataClassification: "public",
		},
	})
	if err != nil {
		t.Fatalf("GCSObjectEvent() error = %v", err)
	}
	if got := event.Attributes["data_classification"]; got != "restricted" {
		t.Fatalf("data_classification = %q, want restricted metadata to win", got)
	}
}

func TestGCSObjectEventAllowsContentClassificationToRaiseSeverity(t *testing.T) {
	event, err := GCSObjectEvent(Settings{ProjectID: "writer-prod"}, GCSObjectRecord{
		ID:       "data/training.csv/1",
		Name:     "training.csv",
		Bucket:   "data",
		Metadata: map[string]string{"data_classification": "internal"},
		ContentInspection: GCSObjectContentInspection{
			Inspected:          true,
			DataClassification: "restricted",
		},
	})
	if err != nil {
		t.Fatalf("GCSObjectEvent() error = %v", err)
	}
	if got := event.Attributes["data_classification"]; got != "restricted" {
		t.Fatalf("data_classification = %q, want restricted content classification to raise severity", got)
	}
}

func TestGCSObjectEventContentPIIEscalatesMetadataPIIFlag(t *testing.T) {
	event, err := GCSObjectEvent(Settings{ProjectID: "writer-prod"}, GCSObjectRecord{
		ID:       "data/training.csv/1",
		Name:     "training.csv",
		Bucket:   "data",
		Metadata: map[string]string{"pii": "false"},
		ContentInspection: GCSObjectContentInspection{
			Inspected:   true,
			ContainsPII: true,
		},
	})
	if err != nil {
		t.Fatalf("GCSObjectEvent() error = %v", err)
	}
	if got := event.Attributes["contains_pii"]; got != "true" {
		t.Fatalf("contains_pii = %q, want content-detected PII to override false metadata", got)
	}
}

func TestInspectGCSObjectContentSampleUsesWholeWordClassification(t *testing.T) {
	inspection := InspectGCSObjectContentSample([]byte("international publication schedule"), false)
	if inspection.DataClassification != "" {
		t.Fatalf("DataClassification = %q, want no incidental substring classification", inspection.DataClassification)
	}
	inspection = InspectGCSObjectContentSample([]byte("confidential launch notes"), false)
	if inspection.DataClassification != "confidential" {
		t.Fatalf("DataClassification = %q, want confidential", inspection.DataClassification)
	}
}
