package main

import (
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/connectorimport"
)

var catalogAPISurfaceShardPattern = regexp.MustCompile(`^.+_(com|io|net|org|local|gov|edu|uk|au|de|nl|ch|eu|hu|za|app|live|ac|co)_.+`)

var catalogRejectedSourcePatterns = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`^(azure_com|googleapis_com|walletobjects_googleapis_com|amazonaws_com|windows_net|github_com|twilio_com)(_|$)`), "provider_api_fragment"},
	{regexp.MustCompile(`(parliament|_gov|gov_|cdcgov|covid|openstates|nytimes|wikimedia|bbc_|npr_|greenpeace|core_ac_uk|ebi_ac_uk|mcw_edu|monarchinitiative|openbanking_org|fec_gov|hhs_gov|ato_gov|codesearch_debian|collegefootballdata)`), "public_or_open_data_api"},
	{regexp.MustCompile(`(sportsdata|spotify|soundcloud|ticketmaster|rawg|tvmaze|flickr|vimeo|bungie|dodo_ac|evetech|pandascore|thebluealliance|spinitron|twitter|medium|dev_to|mastodon|stackexchange|zalando|just_eat|amadeus|britbox|art19|zeno_fm)`), "consumer_media_or_games_api"},
	{regexp.MustCompile(`(adafruit|netatmo|smart_me|corrently|opto22|waterlinked|nebl|tokenjay|axesso|neutrinoapi|peoplegenerator|phantauth|namsor|infermedica|patientview|slicebox|jellyfin|traccar|weatherbit|wordnik|vocadb|trashnothing|nativeads|neowsapp|mon_voyage)`), "consumer_or_iot_api"},
}

func catalogImportRejection(entry manifestTarget) string {
	sourceID := strings.ToLower(strings.TrimSpace(entry.SourceID))
	if sourceID == "" {
		return ""
	}
	if strings.Contains(sourceID, "_local") {
		return "local_or_self_hosted_api"
	}
	for _, rule := range catalogRejectedSourcePatterns {
		if rule.pattern.MatchString(sourceID) {
			return rule.reason
		}
	}
	if catalogAPISurfaceShardPattern.MatchString(sourceID) {
		return "api_surface_shard"
	}
	return ""
}

func rejectedCatalogOutcome(entry manifestTarget, reason string) connectorimport.Outcome {
	return connectorimport.Outcome{
		SourceID: strings.TrimSpace(entry.SourceID),
		Domain:   strings.TrimSpace(entry.Domain),
		Verdict:  connectorimport.VerdictCatalogRejected,
		Error:    reason,
	}
}
