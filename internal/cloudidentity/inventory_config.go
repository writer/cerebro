package cloudidentity

import "strings"

// manifestInventoryConfigMapIndex maps "<namespace>/<name>" ConfigMap data
// from every rendered ConfigMap manifest so container env/config references
// can be resolved to literal, non-secret values without any cluster read.
func manifestInventoryConfigMapIndex(manifests []Manifest) map[string]map[string]string {
	index := make(map[string]map[string]string)
	for _, m := range manifests {
		if manifestInventoryStringField(m.Object, "kind") != "ConfigMap" {
			continue
		}
		namespace, _ := manifestInventoryNestedString(m.Object, "metadata", "namespace")
		name, _ := manifestInventoryNestedString(m.Object, "metadata", "name")
		if name == "" {
			continue
		}
		data := make(map[string]string)
		if raw, ok := manifestInventoryNestedMap(m.Object, "data"); ok {
			for k, v := range raw {
				if s, ok := manifestInventoryAsString(v); ok {
					data[k] = s
				}
			}
		}
		index[namespace+"/"+name] = data
	}
	return index
}

// manifestInventoryContainerConfiguration captures only non-secret literal
// env values and non-secret ConfigMap-sourced values for one container.
// secretKeyRef/secretRef-sourced entries are never included, by name or
// value. An unresolved ConfigMap reference (not present among the rendered
// manifests) becomes a Gap rather than a silently dropped value.
func manifestInventoryContainerConfiguration(container map[string]any, namespace string, configMaps map[string]map[string]string) (map[string]string, []Gap) {
	config := make(map[string]string)
	var gaps []Gap
	containerName := manifestInventoryStringField(container, "name")

	if envs, ok := manifestInventoryAsSlice(container["env"]); ok {
		for _, raw := range envs {
			entry, ok := manifestInventoryAsMap(raw)
			if !ok {
				continue
			}
			name := manifestInventoryStringField(entry, "name")
			if name == "" {
				continue
			}
			if value, ok := manifestInventoryAsString(entry["value"]); ok {
				config[name] = value
				continue
			}
			valueFrom, ok := manifestInventoryAsMap(entry["valueFrom"])
			if !ok {
				continue
			}
			if _, secret := valueFrom["secretKeyRef"]; secret {
				continue
			}
			ref, ok := manifestInventoryAsMap(valueFrom["configMapKeyRef"])
			if !ok {
				continue
			}
			cmName := manifestInventoryStringField(ref, "name")
			key := manifestInventoryStringField(ref, "key")
			data, found := configMaps[namespace+"/"+cmName]
			if !found {
				gaps = append(gaps, manifestInventoryUnresolvedConfigGap(namespace, cmName, containerName))
				continue
			}
			if value, ok := data[key]; ok {
				config[name] = value
			} else {
				gaps = append(gaps, manifestInventoryUnresolvedConfigGap(namespace, cmName+"/"+key, containerName))
			}
		}
	}

	if envFrom, ok := manifestInventoryAsSlice(container["envFrom"]); ok {
		for _, raw := range envFrom {
			entry, ok := manifestInventoryAsMap(raw)
			if !ok {
				continue
			}
			if _, secret := entry["secretRef"]; secret {
				continue
			}
			ref, ok := manifestInventoryAsMap(entry["configMapRef"])
			if !ok {
				continue
			}
			cmName := manifestInventoryStringField(ref, "name")
			prefix := manifestInventoryStringField(entry, "prefix")
			data, found := configMaps[namespace+"/"+cmName]
			if !found {
				gaps = append(gaps, manifestInventoryUnresolvedConfigGap(namespace, cmName, containerName))
				continue
			}
			for k, v := range data {
				config[prefix+k] = v
			}
		}
	}

	return config, gaps
}

func manifestInventoryUnresolvedConfigGap(namespace, ref, container string) Gap {
	return Gap{
		Code:    "cloud_identity.inventory.unresolved_config",
		Scope:   namespace + "/" + ref,
		Message: "container \"" + container + "\" references a ConfigMap value not present among rendered manifests",
	}
}

// manifestInventorySplitImageDigest separates a "repo:tag@sha256:digest" or
// "repo@sha256:digest" image reference into its mutable reference and pinned
// digest, when a digest is present.
func manifestInventorySplitImageDigest(image string) (ref string, digest string) {
	if idx := strings.Index(image, "@sha256:"); idx >= 0 {
		return image[:idx], image[idx+1:]
	}
	return image, ""
}
