package claims

import (
	"strings"

	"github.com/writer/cerebro/sdk/go/cerebroapi"
)

const (
	StatusAsserted = "asserted"

	TypeExistence = "existence"
	TypeAttribute = "attribute"
	TypeRelation  = "relation"

	PredicateExists = "exists"
)

type Source struct {
	SourceEventID string
	ObservedAt    string
	ValidFrom     string
	ValidTo       string
	Attributes    map[string]string
}

func Ref(tenantID, runtimeID, entityType, externalID, label string) cerebroapi.EntityRef {
	encodedExternalID := EncodeExternalID(externalID)
	return cerebroapi.EntityRef{
		URN: strings.Join([]string{
			"urn",
			"cerebro",
			EncodeExternalID(strings.TrimSpace(tenantID)),
			"runtime",
			EncodeExternalID(strings.TrimSpace(runtimeID)),
			EncodeExternalID(strings.TrimSpace(entityType)),
			encodedExternalID,
		}, ":"),
		EntityType: strings.TrimSpace(entityType),
		Label:      label,
	}
}

func EncodeExternalID(value string) string {
	const upperHex = "0123456789ABCDEF"
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' ||
			character == '_' ||
			character == '.' ||
			character == '!' ||
			character == '~' ||
			character == '*' ||
			character == '\'' ||
			character == '(' ||
			character == ')' {
			builder.WriteByte(character)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(upperHex[character>>4])
		builder.WriteByte(upperHex[character&0x0f])
	}
	return builder.String()
}

func Exists(subject cerebroapi.EntityRef, source Source) cerebroapi.Claim {
	claim := base(subject, source)
	claim.Predicate = PredicateExists
	claim.ClaimType = TypeExistence
	return claim
}

func Attribute(subject cerebroapi.EntityRef, predicate string, value string, source Source) cerebroapi.Claim {
	claim := base(subject, source)
	claim.Predicate = predicate
	claim.ObjectValue = value
	claim.ClaimType = TypeAttribute
	return claim
}

func Relation(subject cerebroapi.EntityRef, predicate string, object cerebroapi.EntityRef, source Source) cerebroapi.Claim {
	claim := base(subject, source)
	claim.Predicate = predicate
	claim.ObjectURN = object.URN
	claim.ObjectRef = &object
	claim.ClaimType = TypeRelation
	return claim
}

func base(subject cerebroapi.EntityRef, source Source) cerebroapi.Claim {
	return cerebroapi.Claim{
		SubjectURN:    subject.URN,
		SubjectRef:    subject,
		Status:        StatusAsserted,
		SourceEventID: strings.TrimSpace(source.SourceEventID),
		ObservedAt:    strings.TrimSpace(source.ObservedAt),
		ValidFrom:     strings.TrimSpace(source.ValidFrom),
		ValidTo:       strings.TrimSpace(source.ValidTo),
		Attributes:    copyAttributes(source.Attributes),
	}
}

func copyAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out[key] = trimmed
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
