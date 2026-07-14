package postgres

import (
	"database/sql"
	"testing"
	"time"
)

type fakeScanner struct {
	values []any
}

func (f *fakeScanner) Scan(dest ...any) error {
	for i := range dest {
		switch target := dest[i].(type) {
		case *string:
			*target = f.values[i].(string)
		case *int64:
			*target = f.values[i].(int64)
		case *int:
			*target = f.values[i].(int)
		case *bool:
			*target = f.values[i].(bool)
		case *time.Time:
			*target = f.values[i].(time.Time)
		case *sql.NullTime:
			*target = f.values[i].(sql.NullTime)
		}
	}
	return nil
}

func TestScanReportSchedule(t *testing.T) {
	created := time.Date(2026, 6, 22, 8, 0, 0, 0, time.UTC)
	next := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	last := time.Date(2026, 6, 22, 7, 0, 0, 0, time.UTC)

	t.Run("with last run", func(t *testing.T) {
		scanner := &fakeScanner{values: []any{
			"sched-1", "local", "finding-summary",
			`{"tenant_id":"local","runtime_ids":"rt-1"}`,
			int64(3600), true, next,
			sql.NullTime{Time: last, Valid: true},
			"", sql.NullTime{},
			created, created,
		}}
		schedule, err := scanReportSchedule(scanner)
		if err != nil {
			t.Fatalf("scanReportSchedule() error = %v", err)
		}
		if schedule.ID != "sched-1" || schedule.TenantID != "local" || schedule.ReportID != "finding-summary" {
			t.Fatalf("unexpected identity fields: %+v", schedule)
		}
		if schedule.IntervalSeconds != 3600 || !schedule.Enabled {
			t.Fatalf("unexpected interval/enabled: %+v", schedule)
		}
		if schedule.Parameters["runtime_ids"] != "rt-1" || schedule.Parameters["tenant_id"] != "local" {
			t.Fatalf("unexpected parameters: %+v", schedule.Parameters)
		}
		if !schedule.NextRunAt.Equal(next) || !schedule.LastRunAt.Equal(last) {
			t.Fatalf("unexpected run times: next=%v last=%v", schedule.NextRunAt, schedule.LastRunAt)
		}
	})

	t.Run("never run leaves zero last run", func(t *testing.T) {
		scanner := &fakeScanner{values: []any{
			"sched-2", "local", "risk-delta",
			"",
			int64(7200), false, next,
			sql.NullTime{},
			"", sql.NullTime{},
			created, created,
		}}
		schedule, err := scanReportSchedule(scanner)
		if err != nil {
			t.Fatalf("scanReportSchedule() error = %v", err)
		}
		if !schedule.LastRunAt.IsZero() {
			t.Fatalf("expected zero last run, got %v", schedule.LastRunAt)
		}
		if len(schedule.Parameters) != 0 {
			t.Fatalf("expected empty parameters, got %+v", schedule.Parameters)
		}
	})
}

func TestReportScheduleListLimit(t *testing.T) {
	cases := []struct {
		in   uint32
		want uint32
	}{
		{in: 0, want: 100},
		{in: 25, want: 25},
		{in: 9999, want: 500},
	}
	for _, tc := range cases {
		if got := reportScheduleListLimit(tc.in); got != tc.want {
			t.Fatalf("reportScheduleListLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestReportRunListLimit(t *testing.T) {
	cases := []struct {
		in   uint32
		want uint32
	}{
		{in: 0, want: 50},
		{in: 25, want: 25},
		{in: 9999, want: 200},
	}
	for _, tc := range cases {
		if got := reportRunListLimit(tc.in); got != tc.want {
			t.Fatalf("reportRunListLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
