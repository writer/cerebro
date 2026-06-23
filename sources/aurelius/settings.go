package aurelius

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

const (
	defaultPageSize = 100
	maxPageSize     = 1000
	defaultRegion   = "us-east-1"
)

var (
	// ErrBucketRequired is returned when no S3 bucket is configured.
	ErrBucketRequired = errors.New("bucket is required")
	// ErrPrefixRequired is returned when no S3 key prefix is configured.
	ErrPrefixRequired = errors.New("prefix is required")
	// ErrInvalidPageSize is returned when page_size is not a positive integer.
	ErrInvalidPageSize = errors.New("invalid page_size")
	// ErrTenantIDRequired is returned when no explicit tenant scope is configured.
	ErrTenantIDRequired = errors.New("tenant_id is required")
	// ErrUnsupportedFamily is returned when the family is not one of the known kinds.
	ErrUnsupportedFamily = errors.New("unsupported family")
	// ErrInvalidBucket is returned when the bucket name contains illegal characters.
	ErrInvalidBucket = errors.New("invalid bucket")
)

type settings struct {
	family         string
	bucket         string
	prefix         string
	region         string
	tenantID       string
	roleARN        string
	externalID     string
	assumeRoleARNs string
	perPage        int32
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	tenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "tenant_id"))
	if runtimeTenantID := strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)); runtimeTenantID != "" {
		tenantID = runtimeTenantID
	}
	st := settings{
		family:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")),
		bucket:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "bucket")),
		prefix:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "prefix")),
		region:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "region")),
		tenantID:       tenantID,
		roleARN:        strings.TrimSpace(sourcecdk.ConfigValue(cfg, "role_arn")),
		externalID:     strings.TrimSpace(sourcecdk.ConfigValue(cfg, "external_id")),
		assumeRoleARNs: strings.TrimSpace(sourcecdk.ConfigValue(cfg, sourceconfig.AWSAssumeRoleAllowlistKey)),
		perPage:        defaultPageSize,
	}
	if st.family == "" {
		st.family = familyVerdict
	}
	if st.bucket == "" {
		return settings{}, ErrBucketRequired
	}
	if st.prefix == "" {
		return settings{}, ErrPrefixRequired
	}
	if !strings.HasSuffix(st.prefix, "/") {
		st.prefix += "/"
	}
	if st.region == "" {
		st.region = defaultRegion
	}
	if st.tenantID == "" {
		return settings{}, ErrTenantIDRequired
	}
	if st.roleARN != "" {
		if err := validateAssumeRoleConfig(st); err != nil {
			return settings{}, err
		}
	} else if st.externalID != "" {
		return settings{}, fmt.Errorf("aurelius external_id requires role_arn")
	}
	rawPageSize, ok := cfg.Lookup("per_page")
	if ok && strings.TrimSpace(rawPageSize) != "" {
		size, err := strconv.ParseInt(strings.TrimSpace(rawPageSize), 10, 32)
		if err != nil {
			return settings{}, fmt.Errorf("%w: %w", ErrInvalidPageSize, err)
		}
		if size < 1 {
			return settings{}, fmt.Errorf("%w: must be >= 1", ErrInvalidPageSize)
		}
		if size > int64(maxPageSize) {
			size = int64(maxPageSize)
		}
		st.perPage = int32(size) // #nosec G109 G115 -- ParseInt bitSize 32 and maxPageSize bound ensure this conversion is safe.
	}
	if !isKnownFamily(st.family) {
		return settings{}, fmt.Errorf("%w: %q", ErrUnsupportedFamily, st.family)
	}
	if strings.ContainsRune(st.bucket, '/') {
		return settings{}, fmt.Errorf("%w: %q must not contain slashes", ErrInvalidBucket, st.bucket)
	}
	return st, nil
}

func validateAssumeRoleConfig(st settings) error {
	if len(awsRoleARNPattern.FindStringSubmatch(st.roleARN)) != 3 {
		return fmt.Errorf("aurelius role_arn must be an IAM role ARN")
	}
	if st.tenantID == "" {
		return fmt.Errorf("aurelius role_arn requires runtime tenant_id")
	}
	if !assumeRoleARNAllowed(st.tenantID, st.roleARN, st.assumeRoleARNs) {
		return fmt.Errorf("aurelius role_arn is not allowed")
	}
	return nil
}

func assumeRoleARNAllowed(tenantID string, roleARN string, allowlist string) bool {
	tenantID = strings.TrimSpace(tenantID)
	roleARN = strings.TrimSpace(roleARN)
	if tenantID == "" || roleARN == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		tenant, arn, ok := strings.Cut(strings.TrimSpace(value), "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(tenant) == tenantID && strings.TrimSpace(arn) == roleARN {
			return true
		}
	}
	return false
}
