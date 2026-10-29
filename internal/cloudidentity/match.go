package cloudidentity

import "strings"

// matchState is a tri-state result for policy matching: a confident yes, a
// confident no, or genuinely unknown because of a semantic cloudidentity
// cannot evaluate (omitted resource scope, unsupported condition operator,
// negated principal, ...). Unknown must never collapse into yes or no.
type matchState int

const (
	matchNo matchState = iota
	matchYes
	matchUnknown
)

// globMatch reports whether value matches an AWS-style glob pattern using
// '*' (any run of characters, including none) and '?' (exactly one
// character).
func globMatch(pattern, value string) bool {
	return globMatchRunes([]rune(pattern), []rune(value))
}

func globMatchRunes(pattern, value []rune) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	switch pattern[0] {
	case '*':
		if globMatchRunes(pattern[1:], value) {
			return true
		}
		for i := range value {
			if globMatchRunes(pattern[1:], value[i+1:]) {
				return true
			}
		}
		return false
	case '?':
		if len(value) == 0 {
			return false
		}
		return globMatchRunes(pattern[1:], value[1:])
	default:
		if len(value) == 0 || value[0] != pattern[0] {
			return false
		}
		return globMatchRunes(pattern[1:], value[1:])
	}
}

// awsWildcardMatch matches an AWS action or resource pattern against a
// concrete value. Action matching is case-insensitive per AWS convention;
// resource (ARN) matching is case-sensitive.
func awsWildcardMatch(pattern, value string, foldCase bool) bool {
	if foldCase {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	return globMatch(pattern, value)
}

// literalPrefix returns the literal text of pattern before its first
// wildcard character.
func literalPrefix(pattern string) string {
	if idx := strings.IndexAny(pattern, "*?"); idx >= 0 {
		return pattern[:idx]
	}
	return pattern
}

// resourcePatternsOverlap reports whether two resource patterns could ever
// both match some common concrete resource. It is intentionally
// conservative (biased toward "could overlap") so deny-suppression and
// boundary-coverage checks never understate a restriction, which in turn
// never lets an ambiguous pattern pair manufacture a false excess finding.
// Raw string inequality is NEVER treated as disjoint proof on its own: both
// providers have resource-naming schemes that can alias the same
// underlying resource through textually unrelated strings (GCP project ID
// vs project NUMBER, AWS S3 bucket ARN vs an access-point ARN scoped to
// that same bucket); comparisons are only made hierarchy-precise where the
// two patterns are in a scheme we can actually relate, and conservatively
// overlap otherwise. resolved is Evidence.ResolvedIdentifiers, consulted
// only for the GCP "gcp_project_number:<id>" alias family.
func resourcePatternsOverlap(provider Provider, a, b string, resolved map[string]string) bool {
	if a == "" || b == "" {
		return true
	}
	if a == "*" || b == "*" || a == b {
		return true
	}
	if provider == AWS {
		if awsAccessPointAliasAmbiguous(a, b) {
			return true
		}
		aWild := strings.ContainsAny(a, "*?")
		bWild := strings.ContainsAny(b, "*?")
		switch {
		case !aWild:
			return awsWildcardMatch(b, a, false)
		case !bWild:
			return awsWildcardMatch(a, b, false)
		default:
			pa, pb := literalPrefix(a), literalPrefix(b)
			return strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
		}
	}
	return gcpResourcePatternsOverlap(a, b, resolved)
}

// awsAccessPointAliasAmbiguous reports whether exactly one of a/b is an S3
// access-point ARN (":accesspoint/...") and the other looks like a plain
// bucket/object ARN ("arn:<partition>:s3:::..."). An access point is
// attached to a specific bucket, so requests through it operate on that
// bucket's objects — but the ARN text never names the underlying bucket,
// so we cannot prove or disprove the alias from the strings alone.
func awsAccessPointAliasAmbiguous(a, b string) bool {
	aAP, bAP := strings.Contains(a, ":accesspoint/"), strings.Contains(b, ":accesspoint/")
	if aAP == bAP {
		return false
	}
	plain := a
	if aAP {
		plain = b
	}
	return strings.HasPrefix(plain, "arn:aws:s3:::") ||
		strings.HasPrefix(plain, "arn:aws-us-gov:s3:::") ||
		strings.HasPrefix(plain, "arn:aws-cn:s3:::")
}

// gcpResourcePatternsOverlap applies hierarchy-aware containment only where
// the two resource names are in a scheme whose ancestry we can actually
// read, and conservatively overlaps otherwise.
func gcpResourcePatternsOverlap(a, b string, resolved map[string]string) bool {
	// A short canonical name ("projects/X") and a full resource name
	// ("//service.googleapis.com/projects/X") are different schemes that
	// can name the same resource without any shared text — no ancestry
	// evidence is derivable by comparing them directly.
	if strings.HasPrefix(a, "//") != strings.HasPrefix(b, "//") {
		return true
	}
	// GCS (and similarly modeled services) encode bucket/object resources
	// under a literal "_" placeholder in place of the owning project
	// ("projects/_/buckets/B") precisely because the bucket namespace is
	// global, not project-scoped in the path. That placeholder never
	// reveals which project actually owns the resource, so a project-level
	// pattern can neither be proven to cover nor to exclude it from the
	// string alone — conservatively overlap rather than assert disjoint.
	if (isGCPProjectPattern(a) && gcpHasProjectPlaceholder(b)) ||
		(isGCPProjectPattern(b) && gcpHasProjectPlaceholder(a)) {
		return true
	}
	// Normalize each side's leading "projects/<X>" component to its
	// numeric project number via ResolvedIdentifiers["gcp_project_number:
	// <id>"] before the hierarchy comparison, so a project-ID grant and a
	// numeric-project requirement for the SAME project are recognized as
	// overlapping rather than compared as unrelated literal strings.
	na, numA, unresolvedA := gcpNormalizeProjectComponent(a, resolved)
	nb, numB, unresolvedB := gcpNormalizeProjectComponent(b, resolved)
	if na == nb || strings.HasPrefix(na, nb+"/") || strings.HasPrefix(nb, na+"/") {
		return true
	}
	// Only a mixed ID<->number pair depends on resolving an alias: two
	// project IDs (or two project numbers) are unique strings that can
	// never secretly name the same project, so they compare directly and
	// confidently as disjoint above. An ID side with no
	// "gcp_project_number:<id>" mapping, compared against a NUMBER side,
	// is genuinely unknown — never asserted disjoint from an unresolved
	// mapping.
	if numA != numB && (unresolvedA || unresolvedB) {
		return true
	}
	return false
}

// gcpNormalizeProjectComponent replaces a resource name's leading
// "projects/<id>" component with "projects/<number>" using
// resolved["gcp_project_number:<id>"], so id- and number-addressed
// resource names for the same project compare equal. numeric reports
// whether the component was (or was resolved to) a project number. The
// GCS "_" placeholder is left unchanged: it is a recognized global-bucket
// marker, never a resolvable project identifier. unresolved is true only
// for a non-numeric, non-placeholder project ID with no entry in
// resolved, meaning the alias could not be checked either way.
func gcpNormalizeProjectComponent(resource string, resolved map[string]string) (normalized string, numeric bool, unresolved bool) {
	const marker = "projects/"
	idx := strings.Index(resource, marker)
	if idx < 0 {
		return resource, false, false
	}
	start := idx + len(marker)
	id := resource[start:]
	if end := strings.IndexByte(id, '/'); end >= 0 {
		id = id[:end]
	}
	if id == "" || id == "_" {
		return resource, false, false
	}
	if isAllDigits(id) {
		return resource, true, false
	}
	number, ok := resolved["gcp_project_number:"+id]
	if !ok {
		return resource, false, true
	}
	return resource[:start] + number + resource[start+len(id):], true, false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isGCPProjectPattern reports whether resource names exactly a project
// itself ("projects/X", no further path segments) rather than a resource
// within it.
func isGCPProjectPattern(resource string) bool {
	return strings.HasPrefix(resource, "projects/") && strings.Count(resource, "/") == 1
}

func gcpHasProjectPlaceholder(resource string) bool {
	return strings.Contains(resource, "/_/") || strings.HasPrefix(resource, "_/")
}

// matchActionAgainstGrant reports whether a concrete action is covered by a
// grant's Actions/NotActions. A grant with neither set is ambiguous (should
// not occur for a valid statement; ParseAWSPolicy rejects it, but adapters
// for other providers may still produce one).
func matchActionAgainstGrant(provider Provider, grant Grant, action string) matchState {
	switch {
	case len(grant.Actions) > 0:
		for _, pattern := range grant.Actions {
			if matchActionPattern(provider, pattern, action) {
				return matchYes
			}
		}
		return matchNo
	case len(grant.NotActions) > 0:
		for _, pattern := range grant.NotActions {
			if matchActionPattern(provider, pattern, action) {
				return matchNo
			}
		}
		return matchYes
	default:
		return matchUnknown
	}
}

func matchActionPattern(provider Provider, pattern, action string) bool {
	if provider == AWS {
		return awsWildcardMatch(pattern, action, true)
	}
	return pattern == action
}

// resourcePatternCoverage reports whether a grant's Resources/NotResources
// cover a given resource pattern (itself possibly a wildcard, since both
// sides of this comparison are declarative policy text, not a single
// concrete runtime resource). Omitted Resources is always unknown — it is
// never treated as "*" and never treated as "no resources".
func resourcePatternCoverage(provider Provider, grant Grant, resourcePattern string, resolved map[string]string) matchState {
	switch {
	case len(grant.Resources) > 0:
		covered := false
		for _, p := range grant.Resources {
			if resourcePatternsOverlap(provider, p, resourcePattern, resolved) {
				covered = true
				break
			}
		}
		if !covered {
			return matchNo
		}
		for _, p := range grant.NotResources {
			if resourcePatternsOverlap(provider, p, resourcePattern, resolved) {
				return matchUnknown
			}
		}
		return matchYes
	case len(grant.NotResources) > 0:
		// A pure NotResource grant's positive scope can't be proven to
		// cover (or exclude) an arbitrary pattern without enumerating the
		// universe of resources; treat as unknown rather than guessing.
		return matchUnknown
	default:
		return matchUnknown
	}
}

// resourcePatternContains reports whether every concrete resource matched by
// candidate is also matched by container, so an unconditional Deny scoped to
// container could fully suppress an Allow scoped to candidate. It is
// intentionally conservative: only exact-literal equality, a wildcard
// container ("*"), or a single-trailing-wildcard container whose literal
// prefix is a prefix of candidate's own literal prefix (e.g. "bucket/*"
// containing "bucket/private/*", a bare literal, or a narrower single-
// trailing-wildcard pattern) are proven; anything else (multiple wildcards,
// "?" wildcards, or a container pattern not ending in the trailing "*")
// returns false rather than guessing, since a false positive here would
// wrongly suppress real excess.
func resourcePatternContains(provider Provider, container, candidate string) bool {
	if container == candidate {
		return true
	}
	if container == "*" {
		return candidate != ""
	}
	if provider != AWS {
		return false
	}
	if strings.ContainsRune(container, '?') {
		return false
	}
	if !strings.HasSuffix(container, "*") || strings.Count(container, "*") != 1 {
		return false
	}
	prefix := strings.TrimSuffix(container, "*")
	if strings.ContainsRune(candidate, '?') {
		return false
	}
	if !strings.Contains(candidate, "*") {
		return strings.HasPrefix(candidate, prefix)
	}
	if !strings.HasSuffix(candidate, "*") || strings.Count(candidate, "*") != 1 {
		return false
	}
	return strings.HasPrefix(strings.TrimSuffix(candidate, "*"), prefix)
}

// layerAllows reports whether any Allow grant in layer covers
// action+resourcePattern. When intersectConditions is non-nil (boundary
// layers only — the identity layer never intersects against itself), each
// candidate Allow's own Conditions must also be provably satisfiable
// alongside intersectConditions (the candidate identity grant's own
// Conditions); an unsatisfiable conjunction disqualifies that boundary
// grant, and an unresolvable one degrades the result to unknown rather than
// yes.
func layerAllows(provider Provider, layer []Grant, action, resourcePattern string, intersectConditions []Condition, resolved map[string]string) matchState {
	best := matchNo
	for _, g := range layer {
		if g.Effect != "Allow" {
			continue
		}
		if matchActionAgainstGrant(provider, g, action) != matchYes {
			continue
		}
		switch resourcePatternCoverage(provider, g, resourcePattern, resolved) {
		case matchNo:
			continue
		case matchUnknown:
			best = matchUnknown
			continue
		}
		if intersectConditions != nil {
			switch conditionConjunctionSatisfiable(g.Conditions, intersectConditions) {
			case matchNo:
				continue
			case matchUnknown:
				best = matchUnknown
				continue
			}
		}
		return matchYes
	}
	return best
}

// layerDenies reports whether any Deny grant in layer could apply to
// action+resourcePattern. matchYes (full suppression) requires an
// unconditional Deny (no Conditions, no NotResources) whose Resources
// provably contain candidate's ENTIRE resource pattern — not merely
// overlap it — per AWS evaluation semantics: a narrower-resource or
// conditional Deny only removes part of the Allow's surface, leaving a
// residual the evaluator cannot enumerate, so it degrades to matchUnknown
// rather than being treated as full suppression.
func layerDenies(provider Provider, layer []Grant, action, resourcePattern string, resolved map[string]string) matchState {
	result := matchNo
	for _, g := range layer {
		if g.Effect != "Deny" {
			continue
		}
		if matchActionAgainstGrant(provider, g, action) != matchYes {
			continue
		}
		coverage := resourcePatternCoverage(provider, g, resourcePattern, resolved)
		if coverage == matchNo {
			continue
		}
		if coverage == matchYes && len(g.Conditions) == 0 && len(g.NotResources) == 0 {
			contains := false
			for _, p := range g.Resources {
				if resourcePatternContains(provider, p, resourcePattern) {
					contains = true
					break
				}
			}
			if contains {
				return matchYes
			}
		}
		result = matchUnknown
	}
	return result
}

// effectiveAllow combines an identity layer and its intersecting boundary
// layers (PolicyState.Boundaries) with deny-anywhere precedence, matching
// AWS's evaluation order: a resource is effectively allowed only if the
// identity layer AND every boundary layer allow it, and no layer denies it.
// identityConditions is the candidate identity grant's own Conditions,
// intersected against each boundary layer's Allow grants (never against the
// identity layer itself, which cannot meaningfully intersect with itself).
func effectiveAllow(provider Provider, layers [][]Grant, action, resourcePattern string, identityConditions []Condition, resolved map[string]string) matchState {
	overall := matchYes
	for i, layer := range layers {
		var intersect []Condition
		if i > 0 {
			intersect = identityConditions
			if intersect == nil {
				intersect = []Condition{}
			}
		}
		switch layerAllows(provider, layer, action, resourcePattern, intersect, resolved) {
		case matchNo:
			return matchNo
		case matchUnknown:
			overall = matchUnknown
		}
	}
	for _, layer := range layers {
		switch layerDenies(provider, layer, action, resourcePattern, resolved) {
		case matchYes:
			return matchNo
		case matchUnknown:
			if overall == matchYes {
				overall = matchUnknown
			}
		}
	}
	return overall
}

// effectiveResourcePattern computes the resource pattern actually reachable
// once every boundary layer is intersected with the identity grant's own
// pattern, per AWS permissions-boundary / GCP IAM-condition semantics:
// effective access = identity ∩ boundary1 ∩ boundary2 ... Callers must only
// use this after effectiveAllow has already confirmed the pattern is
// allowed; it narrows the pattern used for excess/narrowing evaluation, it
// does not re-derive whether access is allowed at all. ok is false when the
// provable intersection with some boundary layer cannot be determined as a
// single pattern (an overlapping boundary resource that neither contains
// nor is contained by the running effective pattern) — callers must then
// treat the resource scope as uncertain, never inferring the grant is
// either fully used (fulfillment) or genuinely excess (disjointness) from
// a guessed intersection.
func effectiveResourcePattern(provider Provider, layers [][]Grant, action, pattern string, identityConditions []Condition, resolved map[string]string) (string, bool) {
	effective := pattern
	for i, layer := range layers {
		if i == 0 {
			continue
		}
		intersect := identityConditions
		if intersect == nil {
			intersect = []Condition{}
		}
		narrowed, ok := narrowAgainstLayer(provider, layer, action, effective, intersect, resolved)
		if !ok {
			return "", false
		}
		effective = narrowed
	}
	return effective, true
}

// narrowAgainstLayer narrows effective to the provable intersection of
// effective with a single boundary layer's matching Allow grants (those
// whose action matches and whose own Conditions are provably compatible
// with intersectConditions, the candidate identity grant's own
// Conditions). It collects every resource arm in the layer that overlaps
// effective but is strictly narrower than it (resourcePatternContains
// proves containment), and narrows to the provable intersection of those
// candidates. ok is false when no compatible grant overlaps effective at
// all (should not occur once effectiveAllow has already confirmed the
// layer allows this pattern) or when an overlapping arm's containment with
// effective cannot be proven in either direction — a true union of
// partially-overlapping boundary resources is not representable as one
// pattern, so that case is reported unprovable rather than guessed.
func narrowAgainstLayer(provider Provider, layer []Grant, action, effective string, intersectConditions []Condition, resolved map[string]string) (string, bool) {
	var candidates []string
	anyOverlap := false
	for _, g := range layer {
		if g.Effect != "Allow" {
			continue
		}
		if matchActionAgainstGrant(provider, g, action) != matchYes {
			continue
		}
		if conditionConjunctionSatisfiable(g.Conditions, intersectConditions) != matchYes {
			continue
		}
		for _, p := range g.Resources {
			if !resourcePatternsOverlap(provider, p, effective, resolved) {
				continue
			}
			anyOverlap = true
			switch {
			case resourcePatternContains(provider, p, effective):
				// This boundary arm covers the whole running pattern; it
				// does not narrow it further.
			case resourcePatternContains(provider, effective, p):
				candidates = append(candidates, p)
			default:
				return "", false
			}
		}
	}
	if !anyOverlap {
		return "", false
	}
	if len(candidates) == 0 {
		return effective, true
	}
	narrowed := candidates[0]
	for _, c := range candidates[1:] {
		switch {
		case c == narrowed:
			continue
		case resourcePatternContains(provider, narrowed, c):
			narrowed = c
		case resourcePatternContains(provider, c, narrowed):
		default:
			return "", false
		}
	}
	return narrowed, true
}

// conditionConjunctionSatisfiable reports whether a boundary Allow grant's
// own Conditions could simultaneously hold alongside the candidate identity
// grant's own Conditions for the same request, per AWS/GCP permissions-
// boundary intersection semantics (both condition sets constrain the exact
// same request). matchNo means a supported operator proved an unsatisfiable
// conjunction (e.g. StringEquals on the same key with disjoint value sets);
// matchUnknown means at least one boundary condition could not be resolved
// against the identity's conditions; matchYes requires every boundary
// condition to be positively proven compatible (or unconstrained by the
// identity grant).
func conditionConjunctionSatisfiable(boundaryConditions, identityConditions []Condition) matchState {
	if len(boundaryConditions) == 0 {
		return matchYes
	}
	overall := matchYes
	for _, bc := range boundaryConditions {
		switch matchConjunctionCondition(bc, identityConditions) {
		case matchNo:
			return matchNo
		case matchUnknown:
			overall = matchUnknown
		}
	}
	return overall
}

func matchConjunctionCondition(bc Condition, identityConditions []Condition) matchState {
	if !supportedConditionOperators[bc.Operator] {
		return matchUnknown
	}
	var ic *Condition
	for i := range identityConditions {
		if strings.EqualFold(identityConditions[i].Key, bc.Key) {
			ic = &identityConditions[i]
			break
		}
	}
	if ic == nil {
		// The identity grant places no constraint on this key; the
		// boundary's own condition is independently satisfiable by request
		// context the identity grant never restricts.
		return matchYes
	}
	if (bc.Operator == "StringEquals" || bc.Operator == "Bool") && ic.Operator == bc.Operator {
		if stringSetOverlap(bc.Values, ic.Values) {
			return matchYes
		}
		return matchNo
	}
	return matchUnknown
}

// supportedConditionOperators lists the IAM condition operators cloudidentity
// can evaluate deterministically. Any other operator (including GCP CEL
// expressions, which set Condition.Expression instead of Operator) is
// unsupported and treated as unknown.
var supportedConditionOperators = map[string]bool{
	"StringEquals":    true,
	"StringNotEquals": true,
	"StringLike":      true,
	"StringNotLike":   true,
	"Bool":            true,
}

// principalBoundConditionKeys lists AWS condition keys that constrain the
// REQUESTING PRINCIPAL's own identity rather than per-request context
// cloudidentity can reason about. A grant conditioned on one of these is
// never provably satisfiable or unsatisfiable from the request side alone.
var principalBoundConditionKeys = map[string]bool{
	"aws:principalarn":      true,
	"aws:principalaccount":  true,
	"aws:principalorgid":    true,
	"aws:principalorgpaths": true,
	"aws:principaltype":     true,
	"aws:userid":            true,
	"aws:username":          true,
}

func isPrincipalBoundConditionKey(key string) bool {
	lower := strings.ToLower(key)
	return principalBoundConditionKeys[lower] || strings.HasPrefix(lower, "aws:principaltag/")
}

// grantConditionEffectiveness reports whether a grant's own Conditions let
// it actually apply (binding semantic 2): unconditional is effective
// (matchYes); a supported AWS operator on a non-principal-bound key is
// effective/satisfiable (matchYes); a condition on a principal-bound key,
// an unsupported operator, or a GCP CEL expression other than the literal
// "true" is unknown (matchUnknown — the grant may or may not apply, so no
// excess may be asserted from it, but the surface stays incomplete); a GCP
// CEL literal "false" is inert (matchNo — the binding never applies: no
// excess, no gap). Conditions combine with AND: one inert condition makes
// the whole grant inert regardless of the others; otherwise one unknown
// condition makes the whole grant unknown.
func grantConditionEffectiveness(conditions []Condition) matchState {
	overall := matchYes
	for _, c := range conditions {
		switch singleConditionEffectiveness(c) {
		case matchNo:
			return matchNo
		case matchUnknown:
			overall = matchUnknown
		}
	}
	return overall
}

func singleConditionEffectiveness(c Condition) matchState {
	if c.Operator == "" && c.Expression != "" {
		switch strings.TrimSpace(c.Expression) {
		case "true":
			return matchYes
		case "false":
			return matchNo
		default:
			return matchUnknown
		}
	}
	if isPrincipalBoundConditionKey(c.Key) {
		return matchUnknown
	}
	if !supportedConditionOperators[c.Operator] {
		return matchUnknown
	}
	return matchYes
}

// conditionsCompatible reports whether a grant's own Conditions could apply
// to a requirement's declared Conditions. matchNo means a supported operator
// proved the grant's condition is never satisfied by this requirement's
// known facts (so the grant does not actually serve this requirement);
// matchUnknown means at least one condition could not be resolved either
// way, so the grant must still be treated as potentially covering the
// requirement (never assume excess from ambiguity).
func conditionsCompatible(grantConditions, requirementConditions []Condition) matchState {
	if len(grantConditions) == 0 {
		return matchYes
	}
	overall := matchYes
	for _, gc := range grantConditions {
		switch matchSingleCondition(gc, requirementConditions) {
		case matchNo:
			return matchNo
		case matchUnknown:
			overall = matchUnknown
		}
	}
	return overall
}

func matchSingleCondition(gc Condition, requirementConditions []Condition) matchState {
	if !supportedConditionOperators[gc.Operator] {
		return matchUnknown
	}
	var rc *Condition
	for i := range requirementConditions {
		if strings.EqualFold(requirementConditions[i].Key, gc.Key) {
			rc = &requirementConditions[i]
			break
		}
	}
	if rc == nil {
		return matchUnknown
	}
	switch gc.Operator {
	case "StringEquals", "Bool":
		if stringSetOverlap(gc.Values, rc.Values) {
			return matchYes
		}
		return matchNo
	case "StringNotEquals":
		if stringSetOverlap(gc.Values, rc.Values) {
			return matchNo
		}
		return matchYes
	case "StringLike":
		if wildcardSetOverlap(gc.Values, rc.Values) {
			return matchYes
		}
		return matchNo
	case "StringNotLike":
		if wildcardSetOverlap(gc.Values, rc.Values) {
			return matchNo
		}
		return matchYes
	default:
		return matchUnknown
	}
}

func stringSetOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func wildcardSetOverlap(patterns, values []string) bool {
	for _, p := range patterns {
		for _, v := range values {
			if awsWildcardMatch(p, v, false) {
				return true
			}
		}
	}
	return false
}
