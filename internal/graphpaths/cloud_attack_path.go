package graphpaths

// CloudExposurePrivilegeTraversalRelations are the graph relations allowed in a
// bounded proof that a publicly exposed cloud resource can reach a privileged
// principal without crossing through broad account-hub relationships.
func CloudExposurePrivilegeTraversalRelations() []string {
	return []string{
		"assigned_to",
		"attached_to",
		"can_assume",
		"can_impersonate",
		"depends_on",
		"member_of",
		"runs_as",
	}
}

// CloudExposurePrivilegeTraversalDirectionPredicate is a Cypher predicate over a
// variable-length path named proof_path. Most relations must be followed from
// the exposed node toward the privileged principal. member_of is allowed in the
// reverse direction so a public security group can prove reachability to member
// workloads before the path continues through runtime identity edges.
const CloudExposurePrivilegeTraversalDirectionPredicate = `all(idx IN range(0, length(proof_path) - 1) WHERE
    (
      relationships(proof_path)[idx].relation = 'member_of'
      AND startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx + 1]
    )
    OR (
      relationships(proof_path)[idx].relation <> 'member_of'
      AND startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx]
    )
  )`
