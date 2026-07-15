package grcprogram

import "github.com/writer/cerebro/internal/compliance"

func revisionRefFromVersion(value compliance.VersionMetadata) compliance.RevisionRef {
	return compliance.NormalizeRevisionRef(compliance.RevisionRef{
		ID: value.ID, RevisionID: value.RevisionID, Version: value.Version,
		ContentDigest: value.ContentDigest, LastModified: value.LastModified,
	})
}
