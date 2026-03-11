package apicontract

import _ "embed"

// OpenAPIYAML contains the embedded OpenAPI contract served by /openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPIYAML []byte
