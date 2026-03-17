package runtime

import (
	"fmt"
	"testing"
)

func TestProcessedEventBloomFalsePositiveRate(t *testing.T) {
	filter := newProcessedEventBloom(10000, runtimeProcessedEventBloomFalsePositiveRate)
	if filter == nil {
		t.Fatal("expected bloom filter")
	}

	for i := 0; i < 10000; i++ {
		filter.add(fmt.Sprintf("seen-%d", i))
	}

	for i := 0; i < 10000; i++ {
		if !filter.maybeContains(fmt.Sprintf("seen-%d", i)) {
			t.Fatalf("expected inserted key seen-%d to be present", i)
		}
	}

	falsePositives := 0
	for i := 0; i < 10000; i++ {
		if filter.maybeContains(fmt.Sprintf("unseen-%d", i)) {
			falsePositives++
		}
	}
	if rate := float64(falsePositives) / 10000.0; rate > 0.005 {
		t.Fatalf("false positive rate = %.4f, want <= 0.0050", rate)
	}
}

func TestProcessedEventBloomRebuildSignalBacksOffUntilNextWindow(t *testing.T) {
	filter := newProcessedEventBloom(8, runtimeProcessedEventBloomFalsePositiveRate)
	if filter == nil {
		t.Fatal("expected bloom filter")
	}
	filter.rebuildThreshold = 2
	filter.nextRebuildAt = 2

	if needsRebuild := filter.add("one"); needsRebuild {
		t.Fatal("did not expect rebuild after first insert")
	}
	if needsRebuild := filter.add("two"); !needsRebuild {
		t.Fatal("expected rebuild at threshold")
	}
	if needsRebuild := filter.add("three"); needsRebuild {
		t.Fatal("did not expect immediate rebuild retry after threshold was reached")
	}
	if needsRebuild := filter.add("four"); !needsRebuild {
		t.Fatal("expected rebuild once the next threshold window is reached")
	}
}
