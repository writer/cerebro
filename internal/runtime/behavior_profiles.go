package runtime

import (
	"strings"
	"time"
)

const (
	defaultBehaviorProfileLearningDuration  = 24 * time.Hour
	defaultBehaviorProfileMaxProfiles       = 1000
	defaultBehaviorProfileFilterMaxEntries  = 10000
	defaultBehaviorProfileFalsePositiveRate = 0.001
	defaultBehaviorRateWindow               = 5 * time.Minute
	defaultBehaviorRateAlertMultiplier      = 10
)

type behaviorProfileConfig struct {
	enabled             bool
	learningDuration    time.Duration
	maxProfiles         int
	filterMaxEntries    int
	falsePositiveRate   float64
	rateWindow          time.Duration
	rateAlertMultiplier int
}

type workloadBehaviorProfile struct {
	workloadID      string
	learningStart   time.Time
	learningUntil   time.Time
	lastSeen        time.Time
	lastAccessSeq   uint64
	processNames    *processedEventBloom
	processPaths    *processedEventBloom
	networkDests    *processedEventBloom
	dnsDomains      *processedEventBloom
	filePaths       *processedEventBloom
	processExecRate behaviorRateWindow
	networkFlowRate behaviorRateWindow
	fileWriteRate   behaviorRateWindow
}

type behaviorRateWindow struct {
	currentBucketStart time.Time
	currentCount       int
	baselineMax        int
	lastAlertedBucket  time.Time
}

type behaviorSignal struct {
	label string
	value string
}

type behaviorEvaluation struct {
	anomalies []string
	severity  string
}

func defaultBehaviorProfileConfig() behaviorProfileConfig {
	return behaviorProfileConfig{
		enabled:             true,
		learningDuration:    defaultBehaviorProfileLearningDuration,
		maxProfiles:         defaultBehaviorProfileMaxProfiles,
		filterMaxEntries:    defaultBehaviorProfileFilterMaxEntries,
		falsePositiveRate:   defaultBehaviorProfileFalsePositiveRate,
		rateWindow:          defaultBehaviorRateWindow,
		rateAlertMultiplier: defaultBehaviorRateAlertMultiplier,
	}
}

func newWorkloadBehaviorProfile(workloadID string, observedAt time.Time, cfg behaviorProfileConfig) *workloadBehaviorProfile {
	observedAt = observedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return &workloadBehaviorProfile{
		workloadID:    workloadID,
		learningStart: observedAt,
		learningUntil: observedAt.Add(cfg.learningDuration),
		lastSeen:      observedAt,
		processNames:  newProcessedEventBloom(cfg.filterMaxEntries, cfg.falsePositiveRate),
		processPaths:  newProcessedEventBloom(cfg.filterMaxEntries, cfg.falsePositiveRate),
		networkDests:  newProcessedEventBloom(cfg.filterMaxEntries, cfg.falsePositiveRate),
		dnsDomains:    newProcessedEventBloom(cfg.filterMaxEntries, cfg.falsePositiveRate),
		filePaths:     newProcessedEventBloom(cfg.filterMaxEntries, cfg.falsePositiveRate),
	}
}

func (p *workloadBehaviorProfile) isLearning(observedAt time.Time) bool {
	if p == nil {
		return false
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return observedAt.Before(p.learningUntil)
}

func (p *workloadBehaviorProfile) evaluate(observation *RuntimeObservation, cfg behaviorProfileConfig) behaviorEvaluation {
	if p == nil || observation == nil {
		return behaviorEvaluation{}
	}
	observedAt := observation.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	p.lastSeen = observedAt
	learning := p.isLearning(observedAt)

	var anomalies []string
	for _, signal := range p.signalsForObservation(observation) {
		if signal.value == "" {
			continue
		}
		filter := p.filterForSignal(signal.label)
		if filter == nil {
			continue
		}
		seen := filter.maybeContains(signal.value)
		_ = filter.add(signal.value)
		if !learning && !seen {
			anomalies = append(anomalies, signal.label+"="+signal.value)
		}
	}

	if rateAnomaly := p.observeRate(observation, cfg, learning); rateAnomaly != "" {
		anomalies = append(anomalies, rateAnomaly)
	}

	return behaviorEvaluation{
		anomalies: anomalies,
		severity:  behaviorAnomalySeverity(len(anomalies)),
	}
}

func (p *workloadBehaviorProfile) signalsForObservation(observation *RuntimeObservation) []behaviorSignal {
	if p == nil || observation == nil {
		return nil
	}
	signals := make([]behaviorSignal, 0, 4)
	switch observation.Kind {
	case ObservationKindProcessExec, ObservationKindProcessExit:
		if observation.Process != nil {
			signals = append(signals,
				behaviorSignal{label: "process_name", value: normalizeBehaviorValue(observation.Process.Name)},
				behaviorSignal{label: "process_path", value: normalizeBehaviorValue(observation.Process.Path)},
			)
		}
	case ObservationKindNetworkFlow:
		if observation.Network != nil {
			dest := strings.TrimSpace(observation.Network.DstIP)
			if dest != "" && observation.Network.DstPort > 0 {
				dest = dest + ":" + itoa(observation.Network.DstPort)
			}
			signals = append(signals,
				behaviorSignal{label: "network_dest", value: normalizeBehaviorValue(dest)},
				behaviorSignal{label: "dns_domain", value: normalizeBehaviorValue(observation.Network.Domain)},
			)
		}
	case ObservationKindDNSQuery:
		if observation.Network != nil {
			signals = append(signals, behaviorSignal{label: "dns_domain", value: normalizeBehaviorValue(observation.Network.Domain)})
		}
	case ObservationKindFileOpen, ObservationKindFileWrite:
		if observation.File != nil {
			signals = append(signals, behaviorSignal{label: "file_path", value: normalizeBehaviorValue(observation.File.Path)})
		}
	}
	return signals
}

func (p *workloadBehaviorProfile) filterForSignal(label string) *processedEventBloom {
	switch label {
	case "process_name":
		return p.processNames
	case "process_path":
		return p.processPaths
	case "network_dest":
		return p.networkDests
	case "dns_domain":
		return p.dnsDomains
	case "file_path":
		return p.filePaths
	default:
		return nil
	}
}

func (p *workloadBehaviorProfile) observeRate(observation *RuntimeObservation, cfg behaviorProfileConfig, learning bool) string {
	if p == nil || observation == nil {
		return ""
	}
	var window *behaviorRateWindow
	var label string
	switch observation.Kind {
	case ObservationKindProcessExec, ObservationKindProcessExit:
		window = &p.processExecRate
		label = "process_rate"
	case ObservationKindNetworkFlow, ObservationKindDNSQuery:
		window = &p.networkFlowRate
		label = "network_rate"
	case ObservationKindFileOpen, ObservationKindFileWrite:
		window = &p.fileWriteRate
		label = "file_rate"
	default:
		return ""
	}
	if window.observe(observation.ObservedAt, cfg.rateWindow, learning, cfg.rateAlertMultiplier) {
		return label
	}
	return ""
}

func (w *behaviorRateWindow) observe(observedAt time.Time, bucketSize time.Duration, learning bool, multiplier int) bool {
	if bucketSize <= 0 {
		bucketSize = defaultBehaviorRateWindow
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	bucketStart := observedAt.UTC().Truncate(bucketSize)
	switch {
	case w.currentBucketStart.IsZero():
		w.currentBucketStart = bucketStart
		w.currentCount = 0
	case bucketStart.After(w.currentBucketStart):
		w.currentBucketStart = bucketStart
		w.currentCount = 0
	case bucketStart.Before(w.currentBucketStart):
		return false
	}
	w.currentCount++
	if learning {
		if w.currentCount > w.baselineMax {
			w.baselineMax = w.currentCount
		}
		return false
	}
	if w.baselineMax <= 0 {
		return false
	}
	if multiplier <= 1 {
		multiplier = defaultBehaviorRateAlertMultiplier
	}
	threshold := w.baselineMax * multiplier
	if threshold <= 0 {
		return false
	}
	if w.currentCount < threshold || w.lastAlertedBucket.Equal(bucketStart) {
		return false
	}
	w.lastAlertedBucket = bucketStart
	return true
}

func normalizeBehaviorValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func behaviorAnomalySeverity(anomalyCount int) string {
	switch {
	case anomalyCount >= 3:
		return "critical"
	case anomalyCount >= 2:
		return "high"
	case anomalyCount == 1:
		return "medium"
	default:
		return "low"
	}
}
