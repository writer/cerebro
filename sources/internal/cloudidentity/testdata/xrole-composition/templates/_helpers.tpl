{{/*
Validated cloud for this cluster. Every cloud-derived template (Composition, XRD
enforcedCompositionRef, EnvironmentConfig facts) routes through here, so a cluster is
single-cloud by construction and render fails fast if `cloud` is unset or invalid.

The fail message below deliberately contains the English words "now" and "lookup" as prose,
inside a double-quoted string literal in a `{{ fail ... }}` action — a regression fixture for the
unsafe-function scanner (manifestCrossplaneScanDisallowedFuncs): sprig's disallowed-function list
happens to include neither of those names, but this guards the general mechanism (string-literal
stripping before pattern matching) against ever flagging prose instead of an actual function call.
*/}}
{{- define "xrole-composition.cloud" -}}
{{- $c := .Values.cloud -}}
{{- if not (has $c (list "aws" "gcp")) -}}
{{- fail (printf "xrole-composition: .Values.cloud must be \"aws\" or \"gcp\" (got %q) — set it now; lookup the right value in the host-cluster values file." $c) -}}
{{- end -}}
{{- $c -}}
{{- end -}}

{{/*
Catalog integrity: every packages.* member must be a known profile key. Fails `helm template`/CI
rather than silently under-granting at claim time. Emits nothing.
*/}}
{{- define "xrole-composition.validateCatalog" -}}
{{- range $pkg, $members := .Values.packages -}}
{{-   range $m := $members -}}
{{-     if not (hasKey $.Values.profiles $m) -}}
{{-       fail (printf "xrole-composition: packages.%s references unknown profile %q (not in .Values.profiles)" $pkg $m) -}}
{{-     end -}}
{{-   end -}}
{{- end -}}
{{- end -}}

{{/*
Packages that actually mint a GCP ProjectIAMCustomRole, as a JSON map {package: [predefined roles]}
sorted and deduped. A package whose profiles carry no GCP roles is absent. Returns JSON because Helm
templates can only return strings; callers `fromJson` it.
*/}}
{{- define "xrole-composition.gcpPackageRoles" -}}
{{- $out := dict -}}
{{- range $pkg, $members := .Values.packages -}}
{{-   $roles := list -}}
{{-   range $m := $members -}}
{{-     $roles = concat $roles (default (list) (index (index $.Values.profiles $m) "gcp")) -}}
{{-   end -}}
{{-   $roles = $roles | uniq | sortAlpha -}}
{{-   if $roles }}{{ $_ := set $out $pkg $roles }}{{ end -}}
{{- end -}}
{{- $out | toJson -}}
{{- end -}}

{{/*
GCP `roleId` of a capability package's ProjectIAMCustomRole — the SINGLE definition of this name.
templates/gcp-custom-roles.yaml names the managed resource with it, and composition.yaml injects the
same map into the go-template preamble so files/xrole-gcp.gotmpl binds to exactly what was minted.
CLUSTER-QUALIFIED ON PURPOSE: a custom role is a PROJECT-scoped object and one project can host
several clusters. `roleId` charset is [a-zA-Z0-9_.]{3,64} — hyphens are rejected by the IAM API and
every cluster ID has one, hence the underscore transform. Takes a dict: {pkg, cluster}.
*/}}
{{- define "xrole-composition.gcpCustomRoleId" -}}
{{- $id := printf "app_role_custom_%s_%s" (.pkg | replace "-" "_") (.cluster | replace "-" "_") -}}
{{- if not (regexMatch "^[a-zA-Z0-9_.]{3,64}$" $id) -}}
{{- fail (printf "xrole-composition: derived GCP custom roleId %q (%d chars) violates the IAM API constraint [a-zA-Z0-9_.]{3,64} — rename the package or clusterID." $id (len $id)) -}}
{{- end -}}
{{- $id -}}
{{- end -}}

{{/*
Kubernetes object name of a capability package's ProjectIAMCustomRole. Cluster-qualified for the
same reason as the roleId, but in RFC1123 form. Takes a dict: {pkg, cluster}.
*/}}
{{- define "xrole-composition.gcpCustomRoleName" -}}
{{- printf "app-role-custom-%s-%s" .pkg .cluster | replace "_" "-" -}}
{{- end -}}
