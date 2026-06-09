package kubernetesinternal

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestPodImageDigestsAreSorted(t *testing.T) {
	pod := v1.Pod{Status: v1.PodStatus{ContainerStatuses: []v1.ContainerStatus{
		{Name: "b", ImageID: "registry.example/app@sha256:bbbb"},
		{Name: "a", ImageID: "registry.example/app@sha256:aaaa"},
	}}}
	got := podImageDigests(pod)
	want := []string{"sha256:aaaa", "sha256:bbbb"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("podImageDigests() = %#v, want %#v", got, want)
	}
}
