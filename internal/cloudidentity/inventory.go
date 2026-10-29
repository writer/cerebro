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
// than silently dropping or guessing them.
func Inventory(req InventoryRequest) ([]Workload, []Gap) {
	var gaps []Gap
	serviceAccounts := manifestInventoryServiceAccountIndex(req.Manifests)
	configMaps := manifestInventoryConfigMapIndex(req.Manifests)

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
		annotations, saFound := serviceAccounts[namespace+"/"+saName]
		if !saFound && saName != "default" {
			gaps = append(gaps, Gap{Code: "cloud_identity.inventory.service_account_not_rendered", Scope: namespace + "/" + saName, Message: "ServiceAccount referenced by " + kind + " \"" + name + "\" was not among the rendered manifests; workload-identity annotations are unknown", References: []Reference{m.Reference}})
		}

		var principals []Principal
		var principalGaps []Gap
		switch req.Provider {
		case AWS:
			principals, principalGaps = manifestInventoryAWSPrincipals(req.Cluster, namespace, saName, annotations, req.Account)
		case GCP:
			principals, principalGaps = manifestInventoryGCPPrincipals(req.Cluster, namespace, saName, annotations, req.Project)
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
			config, configGaps := manifestInventoryContainerConfiguration(c.spec, namespace, configMaps)
			gaps = append(gaps, configGaps...)
			config["container_type"] = c.class

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

func manifestInventoryServiceAccountIndex(manifests []Manifest) map[string]map[string]string {
	index := make(map[string]map[string]string)
	for _, m := range manifests {
		if manifestInventoryStringField(m.Object, "kind") != "ServiceAccount" {
			continue
		}
		namespace, _ := manifestInventoryNestedString(m.Object, "metadata", "namespace")
		name, _ := manifestInventoryNestedString(m.Object, "metadata", "name")
		if name == "" {
			continue
		}
		annotations := make(map[string]string)
		if raw, ok := manifestInventoryNestedMap(m.Object, "metadata", "annotations"); ok {
			for k, v := range raw {
				if s, ok := manifestInventoryAsString(v); ok {
					annotations[k] = s
				}
			}
		}
		index[namespace+"/"+name] = annotations
	}
	return index
}
