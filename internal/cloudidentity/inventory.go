package cloudidentity

import "sort"

var manifestInventorySupportedKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "Pod": true,
}

// Inventory converts already-rendered Kubernetes manifests into one Workload
// per container (regular or init), identified by its owning controller
// object so replicas are represented once, while distinct containers within
// one pod template (sidecars, init containers) remain distinct entries.
// Workloads are grouped into logical services via ServiceMapping image
// prefixes; an unmapped image gets an empty Service (never a name invented
// from the workload itself, which downstream sharing evaluation would
// otherwise read as proof of distinct services) plus an unmapped_service
// gap. It performs no I/O; gaps mark unresolved namespace/account/project/
// config/service-mapping references and malformed render output rather
// than silently dropping or guessing them. A ServiceAccount's cloud
// identity annotation is never resolved from conflicting rendered values:
// two ServiceAccount manifests sharing a namespace/name that disagree on
// the AWS IRSA role-arn or GCP Workload Identity annotation produce a
// scoped gap and no authoritative principal, never whichever manifest
// happened to render last.
func Inventory(req InventoryRequest) ([]Workload, []Gap) {
	var gaps []Gap
	serviceAccounts := manifestInventoryServiceAccountIndex(req.Manifests)

	var workloads []Workload
	for _, m := range req.Manifests {
		kind := manifestInventoryStringField(m.Object, "kind")
		if kind == "Rollout" {
			if manifestInventoryAPIGroup(manifestInventoryStringField(m.Object, "apiVersion")) != "argoproj.io" {
				continue
			}
			if _, hasTemplate := manifestInventoryNestedMap(m.Object, "spec", "template"); !hasTemplate {
				if _, hasWorkloadRef := manifestInventoryNestedMap(m.Object, "spec", "workloadRef"); hasWorkloadRef {
					continue
				}
			}
		} else if !manifestInventorySupportedKinds[kind] {
			continue
		}
		name, _ := manifestInventoryNestedString(m.Object, "metadata", "name")
		namespace, _ := manifestInventoryNestedString(m.Object, "metadata", "namespace")
		podSpec, ok := manifestInventoryPodSpec(m.Object, kind)
		if !ok {
			gaps = append(gaps, Gap{Code: "cloud_identity.inventory.pod_spec_missing", Scope: namespace + "/" + name, Message: "kind " + kind + " did not contain the expected pod template spec", References: []Reference{m.Reference}})
			continue
		}
		if namespace == "" {
			gaps = append(gaps, Gap{Code: "cloud_identity.inventory.unresolved_namespace", Scope: name, Message: "rendered manifest has no namespace and none could be stamped from its source", References: []Reference{m.Reference}})
		}

		saName, _ := manifestInventoryAsString(podSpec["serviceAccountName"])
		if saName == "" {
			saName, _ = manifestInventoryAsString(podSpec["serviceAccount"])
		}
		if saName == "" {
			saName = "default"
		}
		saEntry, saFound := serviceAccounts[namespace+"/"+saName]
		if !saFound && saName != "default" {
			gaps = append(gaps, Gap{Code: "cloud_identity.inventory.service_account_not_rendered", Scope: namespace + "/" + saName, Message: "ServiceAccount referenced by " + kind + " \"" + name + "\" was not among the rendered manifests; workload-identity annotations are unknown", References: []Reference{m.Reference}})
		}

		var principals []Principal
		var principalGaps []Gap
		identityAnnotation := manifestInventoryProviderIdentityAnnotation(req.Provider)
		switch {
		case identityAnnotation != "" && saEntry.conflictingAnnotations[identityAnnotation]:
			principalGaps = []Gap{{Code: "cloud_identity.inventory.conflicting_identity_annotation", Scope: namespace + "/" + saName, Message: "ServiceAccount \"" + saName + "\" was rendered with conflicting " + identityAnnotation + " annotation values; no principal can be authoritatively determined", References: []Reference{m.Reference}}}
		case req.Provider == AWS:
			principals, principalGaps = manifestInventoryAWSPrincipals(req.Cluster, namespace, saName, saEntry.annotations, req.Account)
		case req.Provider == GCP:
			principals, principalGaps = manifestInventoryGCPPrincipals(req.Cluster, namespace, saName, saEntry.annotations, req.Project)
		default:
			principalGaps = []Gap{{Code: "cloud_identity.inventory.unsupported_provider", Scope: namespace + "/" + name, Message: "InventoryRequest.Provider is neither aws nor gcp"}}
		}
		gaps = append(gaps, principalGaps...)

		containers := manifestInventoryContainerList(podSpec, "containers", "container")
		containers = append(containers, manifestInventoryContainerList(podSpec, "initContainers", "init")...)
		if len(containers) == 0 {
			gaps = append(gaps, Gap{Code: "cloud_identity.inventory.container_image_missing", Scope: namespace + "/" + name, Message: "pod template for " + kind + " \"" + name + "\" declares no containers", References: []Reference{m.Reference}})
			continue
		}

		for _, c := range containers {
			image, _ := manifestInventoryAsString(c.spec["image"])
			if image == "" {
				gaps = append(gaps, Gap{Code: "cloud_identity.inventory.container_image_missing", Scope: namespace + "/" + name + "/" + c.name, Message: "container \"" + c.name + "\" has no image", References: []Reference{m.Reference}})
				continue
			}
			imageRef, imageDigest := manifestInventorySplitImageDigest(image)
			service, serviceMatched, serviceAmbiguous := manifestInventoryMatchService(imageRef, name, req.Services)
			// Configuration carries only collector-derived nonsecret
			// metadata keys (container_type here; identity_binding_kind is
			// added by collection_principal.go for ACK Pod Identity
			// associations), never literal container env values or
			// ConfigMap data: those are model-input material, and this
			// Workload's evidence is forwarded verbatim to an investigator
			// prompt.
			config := map[string]string{"container_type": c.class}

			var source SourcePin
			switch {
			case serviceMatched:
				source = SourcePin{Repository: service.Repository, Root: service.SourceRoot}
			case serviceAmbiguous:
				gaps = append(gaps, Gap{Code: "cloud_identity.inventory.ambiguous_service_mapping", Scope: namespace + "/" + name + "/" + c.name, Message: "image \"" + imageRef + "\" matched multiple equally-specific ServiceMapping entries for workload \"" + name + "\"; service grouping is ambiguous, not guessed", References: []Reference{m.Reference}})
			default:
				gaps = append(gaps, Gap{Code: "cloud_identity.inventory.unmapped_service", Scope: namespace + "/" + name + "/" + c.name, Message: "image \"" + imageRef + "\" matched no configured ServiceMapping; its service grouping/app-source routing is unproven, not confirmed distinct", References: []Reference{m.Reference}})
			}
			workloads = append(workloads, Workload{
				ID:             manifestInventoryWorkloadID(req.Cluster, namespace, kind, name, c.class, c.name),
				Service:        service.Service,
				Environment:    req.Environment,
				Cluster:        req.Cluster,
				CloudAccount:   req.Account,
				CloudProject:   req.Project,
				Region:         req.Region,
				Namespace:      namespace,
				Name:           name,
				Kind:           kind,
				ServiceAccount: saName,
				Image:          image,
				ImageDigest:    imageDigest,
				Source:         source,
				Principals:     principals,
				Configuration:  config,
				References:     []Reference{m.Reference},
			})
		}
	}

	sort.Slice(workloads, func(i, j int) bool { return workloads[i].ID < workloads[j].ID })
	return workloads, gaps
}

type manifestInventoryContainer struct {
	name  string
	class string
	spec  map[string]any
}

func manifestInventoryContainerList(podSpec map[string]any, field, class string) []manifestInventoryContainer {
	raw, ok := manifestInventoryAsSlice(podSpec[field])
	if !ok {
		return nil
	}
	var out []manifestInventoryContainer
	for _, v := range raw {
		spec, ok := manifestInventoryAsMap(v)
		if !ok {
			continue
		}
		out = append(out, manifestInventoryContainer{name: manifestInventoryStringField(spec, "name"), class: class, spec: spec})
	}
	return out
}

func manifestInventoryPodSpec(obj map[string]any, kind string) (map[string]any, bool) {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "Rollout":
		return manifestInventoryNestedMap(obj, "spec", "template", "spec")
	case "CronJob":
		return manifestInventoryNestedMap(obj, "spec", "jobTemplate", "spec", "template", "spec")
	case "Pod":
		return manifestInventoryNestedMap(obj, "spec")
	default:
		return nil, false
	}
}

// manifestInventoryServiceAccountEntry is one namespace/name
// ServiceAccount's merged rendered annotations, plus which (if any)
// identity-establishing annotation keys
// (manifestInventoryIdentityAnnotationKeys) carried two or more distinct
// values across the ServiceAccount manifests that share this
// namespace/name.
type manifestInventoryServiceAccountEntry struct {
	annotations            map[string]string
	conflictingAnnotations map[string]bool
}

// manifestInventoryIdentityAnnotationKeys are the annotation keys that
// configure a ServiceAccount's cloud identity. Two ServiceAccount manifests
// for the same namespace/name disagreeing on one of these is a genuine
// identity conflict -- which value is authoritative is genuinely unknown --
// never resolved by picking whichever manifest happened to render last.
var manifestInventoryIdentityAnnotationKeys = []string{
	manifestInventoryAnnotationIRSARole,
	manifestInventoryAnnotationGCPGSA,
}

// manifestInventoryProviderIdentityAnnotation returns the single identity
// annotation key relevant to provider ("" for an unsupported provider), so
// callers can check manifestInventoryServiceAccountEntry.conflictingAnnotations
// for exactly the key that would otherwise feed principal construction.
func manifestInventoryProviderIdentityAnnotation(provider Provider) string {
	switch provider {
	case AWS:
		return manifestInventoryAnnotationIRSARole
	case GCP:
		return manifestInventoryAnnotationGCPGSA
	default:
		return ""
	}
}

// manifestInventoryServiceAccountIndex merges every rendered ServiceAccount
// manifest's annotations by namespace/name, and separately records which
// identity-establishing annotation keys were observed with more than one
// distinct non-empty value across those manifests -- regardless of
// rendering order, and regardless of whether an intervening manifest for
// the same ServiceAccount omitted the annotation entirely. Identical
// duplicate annotation values across manifests are never a conflict.
func manifestInventoryServiceAccountIndex(manifests []Manifest) map[string]manifestInventoryServiceAccountEntry {
	index := make(map[string]manifestInventoryServiceAccountEntry)
	observedValues := make(map[string]map[string]map[string]bool)
	for _, m := range manifests {
		if manifestInventoryStringField(m.Object, "kind") != "ServiceAccount" {
			continue
		}
		namespace, _ := manifestInventoryNestedString(m.Object, "metadata", "namespace")
		name, _ := manifestInventoryNestedString(m.Object, "metadata", "name")
		if name == "" {
			continue
		}
		key := namespace + "/" + name
		annotations := make(map[string]string)
		if raw, ok := manifestInventoryNestedMap(m.Object, "metadata", "annotations"); ok {
			for k, v := range raw {
				if s, ok := manifestInventoryAsString(v); ok {
					annotations[k] = s
				}
			}
		}
		entry := index[key]
		entry.annotations = annotations
		index[key] = entry

		if observedValues[key] == nil {
			observedValues[key] = make(map[string]map[string]bool)
		}
		for _, annotationKey := range manifestInventoryIdentityAnnotationKeys {
			value, present := annotations[annotationKey]
			if !present || value == "" {
				continue
			}
			values := observedValues[key][annotationKey]
			if values == nil {
				values = make(map[string]bool)
				observedValues[key][annotationKey] = values
			}
			values[value] = true
		}
	}
	for key, perAnnotation := range observedValues {
		for annotationKey, values := range perAnnotation {
			if len(values) <= 1 {
				continue
			}
			entry := index[key]
			if entry.conflictingAnnotations == nil {
				entry.conflictingAnnotations = make(map[string]bool)
			}
			entry.conflictingAnnotations[annotationKey] = true
			index[key] = entry
		}
	}
	return index
}
