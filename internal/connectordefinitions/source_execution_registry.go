package connectordefinitions

type sourceExecutionKernelSpec struct {
	providerKernel      string
	origin              string
	method              string
	path                string
	recordSelector      string
	idField             string
	singletonFallbackID string
}

var sourceExecutionKernelRegistry = map[string]sourceExecutionKernelSpec{
	"azure\x00authorization_policy": {
		providerKernel: "azure.authorization_policy", origin: "https://graph.microsoft.com",
		method: "GET", path: "/v1.0/policies/authorizationPolicy", recordSelector: "$",
		idField: "id", singletonFallbackID: "authorizationPolicy",
	},
}

func registeredSourceExecutionKernel(sourceID, familyID string) (sourceExecutionKernelSpec, bool) {
	spec, ok := sourceExecutionKernelRegistry[sourceID+"\x00"+familyID]
	return spec, ok
}
