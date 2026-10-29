package cloudidentitysource

import ci "github.com/writer/cerebro/internal/cloudidentity"

// gcpMethodReferenceSource documents where this table comes from. Unlike AWS,
// GCP does not publish a live HTTPS endpoint that maps an API method to its
// required IAM permission(s) (AWS has the Service Authorization Reference
// JSON). The authoritative live source for GCP is the IAM permissions
// reference docs, which are prose/tables, not a queryable API. This table is
// therefore a maintained, explicitly-cited static asset, not a snapshot of
// role contents (roles themselves are always resolved live via
// gcpClient.getRole).
//
// Every entry below is checked against the specific primary GCP method
// documentation for that exact call (cited per-entry doc URL), not inferred
// from the service's general IAM permissions-reference index page.
// DependenciesComplete is only true when that primary doc confirms the full
// potential permission upper bound, Permissions plus ConditionalPermissions
// together; an entry whose upper bound this agent could not fully confirm
// stays in the table as a candidate (DependenciesComplete: false) rather than
// being deleted or overstated.
//
// SDKMethods values are the literal token the requirements extractor
// records at a call site
// (internal/cloudidentity/requirements/static_go.go). For a bare top-level
// client call this is simply the Go method name (e.g. "AccessSecretVersion",
// "Decrypt", "Log"). For a call reached through one of the recognized fluent
// resource accessors (Bucket, Object, Topic, Subscription, Dataset, Table,
// Instance, Database, Secret, Query), the extractor instead records a
// dot-qualified "<ImmediateAccessor>.<Method>" token (e.g. "Object.NewReader"
// for client.Bucket(b).Object(o).NewReader(ctx), "Topic.Publish" for
// client.Topic(id).Publish(ctx, msg)) — never a longer receiver-chain string
// like "StorageClient.Bucket.Object.NewReader". A bare method name that is
// ambiguous within one service when reached WITHOUT a recognized immediate
// accessor (ambiguity rejection currently applies to the storage and
// bigquery services specifically) is left OUT of this table rather than
// mapped to one of several possibilities and risk silently validating the
// wrong one. Likewise a requested method with no entry here is an explicit
// Gap when Define is asked to resolve it; this table is never padded to
// look complete.

// gcpMethodReferenceEntry is one documented GCP API method -> IAM permission
// mapping used to populate ci.Definitions.Operations. Permissions are always
// required; ConditionalPermissions are required too but only resolvable at
// the specific resource/parameter in play (e.g. whether a Cloud Storage
// write overwrites an existing object, or which tables a BigQuery query
// references) which this static, call-site-free table cannot determine —
// the downstream source validator retains ConditionalPermissions
// conservatively rather than dropping them.
type gcpMethodReferenceEntry struct {
	Service                string
	SDKServices            []string
	Operation              string
	SDKMethods             []string
	Permissions            []string
	ConditionalPermissions []string
	DependenciesComplete   bool
	DocURL                 string
}

// gcpMethodReferenceTable lists Kubernetes-workload-relevant GCP Go client
// library calls and the IAM permission(s) each one requires. It is
// intentionally bounded and deliberately omits several commonly-assumed
// mappings this agent could not verify against a specific primary method doc
// at all (e.g. Cloud SQL admin-plane reads, direct BigQuery table row reads)
// rather than guess.
var gcpMethodReferenceTable = []gcpMethodReferenceEntry{
	// Secret Manager: cloud.google.com/go/secretmanager/apiv1 Client methods.
	// Service derives directly from the import path ("secretmanager"), which
	// already equals the IAM permission namespace, so no SDKServices alias.
	// Each is a single unconditional permission per its REST method doc.
	{
		Service: "secretmanager", Operation: "secretmanager.accessSecretVersion",
		SDKMethods: []string{"AccessSecretVersion"}, Permissions: []string{"secretmanager.versions.access"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access",
	},
	{
		Service: "secretmanager", Operation: "secretmanager.getSecretVersion",
		SDKMethods: []string{"GetSecretVersion"}, Permissions: []string{"secretmanager.versions.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/get",
	},
	{
		Service: "secretmanager", Operation: "secretmanager.getSecret",
		SDKMethods: []string{"GetSecret"}, Permissions: []string{"secretmanager.secrets.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/get",
	},
	{
		Service: "secretmanager", Operation: "secretmanager.listSecrets",
		SDKMethods: []string{"ListSecrets"}, Permissions: []string{"secretmanager.secrets.list"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list",
	},

	// Cloud Storage: cloud.google.com/go/storage ObjectHandle/BucketHandle
	// methods, all reached as client.Bucket(b).Object(o).Method(...) or
	// client.Bucket(b).Method(...), so the extractor records a
	// "<ImmediateAccessor>.<Method>" token for every one of these, never a
	// bare method name. NewWriter always needs objects.create; it ALSO needs
	// objects.delete, but only when it overwrites an existing object, which
	// this static table cannot know per call site, so that permission is
	// conditional. Its upper bound is not marked complete: CMEK/retention
	// buckets may require further permissions this entry does not confirm.
	{
		Service: "storage", Operation: "storage.objects.get",
		SDKMethods: []string{"Object.NewReader"}, Permissions: []string{"storage.objects.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/storage/docs/json_api/v1/objects/get",
	},
	{
		Service: "storage", Operation: "storage.objects.list",
		SDKMethods: []string{"Bucket.Objects"}, Permissions: []string{"storage.objects.list"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/storage/docs/json_api/v1/objects/list",
	},
	{
		Service: "storage", Operation: "storage.objects.insert",
		SDKMethods: []string{"Object.NewWriter"}, Permissions: []string{"storage.objects.create"},
		ConditionalPermissions: []string{"storage.objects.delete"},
		DependenciesComplete:   false,
		DocURL:                 "https://cloud.google.com/storage/docs/json_api/v1/objects/insert",
	},
	// Object.Attrs/Bucket.Attrs issue their REST get request with
	// Projection("full") (see http_client.go in the SDK source), which the
	// primary Objects.get/Buckets.get docs confirm can additionally
	// require getIamPolicy (and, for buckets, getIpFilter) depending on
	// the caller's role; these are included as conditional permissions so
	// the full documented upper bound is never understated while still
	// marking the dependency set complete (the base + conditional set
	// together IS the confirmed upper bound).
	{
		Service: "storage", Operation: "storage.objects.get.attrs",
		SDKMethods: []string{"Object.Attrs"}, Permissions: []string{"storage.objects.get"},
		ConditionalPermissions: []string{"storage.objects.getIamPolicy"},
		DependenciesComplete:   true,
		DocURL:                 "https://cloud.google.com/storage/docs/json_api/v1/objects/get",
	},
	{
		Service: "storage", Operation: "storage.buckets.get.attrs",
		SDKMethods: []string{"Bucket.Attrs"}, Permissions: []string{"storage.buckets.get"},
		ConditionalPermissions: []string{"storage.buckets.getIamPolicy", "storage.buckets.getIpFilter"},
		DependenciesComplete:   true,
		DocURL:                 "https://cloud.google.com/storage/docs/json_api/v1/buckets/get",
	},
	{
		Service: "storage", Operation: "storage.objects.delete",
		SDKMethods: []string{"Object.Delete"}, Permissions: []string{"storage.objects.delete"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/storage/docs/json_api/v1/objects/delete",
	},
	{
		Service: "storage", Operation: "storage.buckets.delete",
		SDKMethods: []string{"Bucket.Delete"}, Permissions: []string{"storage.buckets.delete"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/storage/docs/json_api/v1/buckets/delete",
	},

	// Pub/Sub: cloud.google.com/go/pubsub (high-level Topic.Publish,
	// Subscription.Receive) and cloud.google.com/go/pubsub/apiv1
	// (low-level SubscriberClient.Pull/StreamingPull/GetSubscription); both
	// import paths derive the same "pubsub" service.
	{
		Service: "pubsub", Operation: "pubsub.topics.publish",
		SDKMethods: []string{"Topic.Publish"}, Permissions: []string{"pubsub.topics.publish"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics/publish",
	},
	{
		Service: "pubsub", Operation: "pubsub.subscriptions.consume.receive",
		SDKMethods: []string{"Subscription.Receive"}, Permissions: []string{"pubsub.subscriptions.consume"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/pubsub/docs/pull",
	},
	{
		Service: "pubsub", Operation: "pubsub.subscriptions.consume.pull",
		SDKMethods: []string{"Pull", "StreamingPull"}, Permissions: []string{"pubsub.subscriptions.consume"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/pull",
	},
	{
		Service: "pubsub", Operation: "pubsub.subscriptions.get",
		SDKMethods: []string{"GetSubscription"}, Permissions: []string{"pubsub.subscriptions.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/get",
	},

	// BigQuery: cloud.google.com/go/bigquery. Query.Read is the documented
	// shorthand for Query.Run+Job.Read that actually submits the query job;
	// Query() itself performs no call. Running the job needs jobs.create at
	// the project; the referenced tables' getData permission cannot be
	// resolved statically (no literal table list at the call site), so it
	// is conditional. The query text itself is not statically analyzable,
	// so a query against an external connection or a BigQuery ML model can
	// require bigquery.connections.use / bigquery.models.getData beyond
	// these two; this entry is not a bounded upper proof for every query
	// shape. Dataset.Metadata() (bigquery.datasets.get) and Table.Metadata()
	// (bigquery.tables.get) shared the identical bare token "Metadata";
	// the extractor now qualifies by chain accessor ("Dataset.Metadata" /
	// "Table.Metadata"), so both are mapped distinctly below.
	{
		Service: "bigquery", Operation: "bigquery.jobs.query",
		SDKMethods: []string{"Query.Read"}, Permissions: []string{"bigquery.jobs.create"},
		ConditionalPermissions: []string{"bigquery.tables.getData"},
		DependenciesComplete:   false,
		DocURL:                 "https://cloud.google.com/bigquery/docs/running-queries",
	},
	{
		Service: "bigquery", Operation: "bigquery.tables.get",
		SDKMethods: []string{"Table.Metadata"}, Permissions: []string{"bigquery.tables.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/bigquery/docs/reference/rest/v2/tables/get",
	},
	{
		Service: "bigquery", Operation: "bigquery.datasets.get",
		SDKMethods: []string{"Dataset.Metadata"}, Permissions: []string{"bigquery.datasets.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets/get",
	},

	// Cloud KMS: cloud.google.com/go/kms/apiv1 KeyManagementClient. The
	// import path derives service "kms", but the IAM permission namespace is
	// "cloudkms"; SDKServices records the SDK-derived alias.
	{
		Service: "cloudkms", SDKServices: []string{"kms"}, Operation: "cloudkms.cryptoKeyVersions.useToDecrypt",
		SDKMethods: []string{"Decrypt"}, Permissions: []string{"cloudkms.cryptoKeyVersions.useToDecrypt"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/kms/docs/reference/permissions-and-roles",
	},
	{
		Service: "cloudkms", SDKServices: []string{"kms"}, Operation: "cloudkms.cryptoKeyVersions.useToEncrypt",
		SDKMethods: []string{"Encrypt"}, Permissions: []string{"cloudkms.cryptoKeyVersions.useToEncrypt"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/kms/docs/reference/permissions-and-roles",
	},

	// Cloud SQL: cloud.google.com/go/cloudsqlconn Dialer.Dial. The import
	// path derives service "cloudsqlconn"; the IAM permission namespace is
	// "cloudsql". The connector also calls the Cloud SQL Admin API
	// internally to resolve connection metadata/certs before dialing, and
	// this entry does not confirm that admin-plane call's own permission
	// requirement is fully covered by instances.connect alone, so its upper
	// bound stays unconfirmed.
	{
		Service: "cloudsql", SDKServices: []string{"cloudsqlconn"}, Operation: "cloudsql.instances.connect",
		SDKMethods: []string{"Dial"}, Permissions: []string{"cloudsql.instances.connect"},
		DependenciesComplete: false,
		DocURL:               "https://cloud.google.com/sql/docs/mysql/roles-and-permissions",
	},

	// Firestore (Native mode): cloud.google.com/go/firestore DocumentRef
	// methods. The import path derives service "firestore"; Firestore
	// Native mode's IAM permissions live under the "datastore" namespace, so
	// SDKServices records the alias. Every one of these is reached through
	// the real DocumentRef accessor chain (client.Doc(path).Method(...) or
	// client.Collection(id).Doc(path).Method(...)), both proven pure local
	// handle constructors (see requirementsGoGCPServiceAccessors), so the
	// extractor records a qualified "Doc.<Method>" token, never a bare one.
	// Set can create a new document or replace an existing one, and the
	// server cannot know statically which applies, so its documented
	// required-permissions entry lists both — confirmed directly against
	// the Native-mode IAM method table.
	{
		Service: "datastore", SDKServices: []string{"firestore"}, Operation: "datastore.documents.set",
		SDKMethods: []string{"Doc.Set"}, Permissions: []string{"datastore.entities.create", "datastore.entities.update"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/firestore/native/docs/security/iam",
	},
	{
		Service: "datastore", SDKServices: []string{"firestore"}, Operation: "datastore.documents.create",
		SDKMethods: []string{"Doc.Create"}, Permissions: []string{"datastore.entities.create"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/firestore/native/docs/security/iam",
	},
	{
		Service: "datastore", SDKServices: []string{"firestore"}, Operation: "datastore.documents.get",
		SDKMethods: []string{"Doc.Get"}, Permissions: []string{"datastore.entities.get"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/firestore/native/docs/security/iam",
	},
	{
		Service: "datastore", SDKServices: []string{"firestore"}, Operation: "datastore.documents.delete",
		SDKMethods: []string{"Doc.Delete"}, Permissions: []string{"datastore.entities.delete"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/firestore/native/docs/security/iam",
	},

	// Cloud Logging: cloud.google.com/go/logging Logger(id).Log(entry).
	// Logger is a proven pure local handle constructor (no RPC), so the
	// extractor records the qualified "Logger.Log" token.
	{
		Service: "logging", Operation: "logging.entries.create",
		SDKMethods: []string{"Logger.Log"}, Permissions: []string{"logging.logEntries.create"},
		DependenciesComplete: true,
		DocURL:               "https://cloud.google.com/logging/docs/reference/rest/v2/entries/write",
	},

	// Spanner: cloud.google.com/go/spanner. The real read-only query path
	// is client.Single().Query(ctx, stmt): Single() is a proven pure local
	// handle constructor (no RPC) for a ReadOnlyTransaction, so the
	// extractor records the qualified "Single.Query" token, never a bare
	// one. A read/query always needs a session, which the client library
	// manages transparently rather than as a distinct call the extractor
	// could statically see, so it is conditional alongside the
	// unconditional select permission. "Query" is also exposed on
	// ReadWriteTransaction, not only the read-only Client.Single() path
	// used here; a call inside a read-write transaction additionally needs
	// the transaction's own begin/commit permissions, which this entry
	// does not capture, so it is not a bounded upper proof for every call
	// site.
	{
		Service: "spanner", Operation: "spanner.databases.select",
		SDKMethods: []string{"Single.Query"}, Permissions: []string{"spanner.databases.select"},
		ConditionalPermissions: []string{"spanner.sessions.create"},
		DependenciesComplete:   false,
		DocURL:                 "https://cloud.google.com/spanner/docs/iam",
	},
}

// gcpMethodReferenceOperations renders the static table into core
// OperationDefinitions, each carrying a citation to the documented, static
// (non-live) source instead of an ObservedAt timestamp, since this is a
// maintained asset rather than a point-in-time provider observation.
func gcpMethodReferenceOperations() []ci.OperationDefinition {
	operations := make([]ci.OperationDefinition, 0, len(gcpMethodReferenceTable))
	for _, entry := range gcpMethodReferenceTable {
		// Every field is a string, string slice, or bool; JSON encoding cannot fail.
		digest, _ := digestStruct(entry)
		operations = append(operations, ci.OperationDefinition{
			Provider:               ci.GCP,
			Service:                entry.Service,
			SDKServices:            entry.SDKServices,
			Operation:              entry.Operation,
			SDKMethods:             entry.SDKMethods,
			Permissions:            entry.Permissions,
			ConditionalPermissions: entry.ConditionalPermissions,
			DependenciesComplete:   entry.DependenciesComplete,
			References: []ci.Reference{{
				API:    entry.DocURL,
				Scope:  "static-reference",
				Digest: digest,
			}},
		})
	}
	return operations
}
