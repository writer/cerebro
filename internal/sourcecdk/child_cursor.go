package sourcecdk

import (
	"fmt"
	"strconv"
	"strings"
)

const ChildPageCursorMode = "child_page"

func DecodeChildPageCursor(source string, family string, opaque string) (string, int, string, bool, error) {
	envelope, ok := DecodeCursorEnvelope(opaque)
	if !ok || strings.TrimSpace(envelope.Source) != strings.TrimSpace(source) || strings.TrimSpace(envelope.Family) != strings.TrimSpace(family) || strings.TrimSpace(envelope.Mode) != ChildPageCursorMode {
		return opaque, 0, "", false, nil
	}
	index := 0
	if raw := strings.TrimSpace(envelope.Extra["parent_index"]); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return "", 0, "", true, fmt.Errorf("%w: invalid child cursor parent index", ErrInvalidConfig)
		}
		index = parsed
	}
	return envelope.Token, index, strings.TrimSpace(envelope.Extra["child_token"]), true, nil
}

func EncodeChildPageCursor(source string, family string, parentToken string, parentIndex int, childToken string) string {
	extra := map[string]string{"parent_index": strconv.Itoa(parentIndex)}
	if strings.TrimSpace(childToken) != "" {
		extra["child_token"] = strings.TrimSpace(childToken)
	}
	opaque, err := EncodeCursorEnvelope(CursorEnvelope{
		Source: strings.TrimSpace(source),
		Family: strings.TrimSpace(family),
		Mode:   ChildPageCursorMode,
		Token:  parentToken,
		Extra:  extra,
	})
	if err != nil {
		return ""
	}
	return opaque
}

func NextChildPageCursor(source string, family string, parentToken string, nextParent string, nextIndex int, parentCount int) string {
	if nextIndex < parentCount {
		return EncodeChildPageCursor(source, family, parentToken, nextIndex, "")
	}
	return strings.TrimSpace(nextParent)
}
