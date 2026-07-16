# Self-authoring policy tests

`testauthor` turns a bounded policy intent into a policy and an executable finding/passing test suite. It can also scan existing policies and author missing suites when every condition is a simple scalar equality.

The authoring boundary is deliberate. The tool accepts `cmp_eq(path(resource, "field"), scalar)` conditions. It rejects query, graph, inequality, collection, and compound-expression semantics until a generator has an explicit fixture contract for them.

## Author a policy and its tests

Create a strict YAML intent:

```yaml
id: aws-s3-public-access
domain: aws
name: S3 public access
description: Flags buckets with public access enabled.
severity: high
resource: aws::s3::bucket
conditions:
  - cmp_eq(path(resource, "public"), true)
frameworks:
  - name: CIS
    controls: [2.1.5]
remediation: Block public access.
```

Preview both artifacts, then write them:

```sh
go run ./tools/testauthor author-policy --intent intent.yaml
go run ./tools/testauthor author-policy --intent intent.yaml --write
go run ./tools/findingdsl test policies/aws/aws-s3-public-access.test.yaml
```

The write is refused if either target exists. Before writing, the command renders both artifacts twice, requires byte-identical output, validates both artifacts, and executes the finding and passing cases against the authored policy.

## Fill supported repository gaps

```sh
go run ./tools/testauthor scan --root .
go run ./tools/testauthor author-tests --root .
go run ./tools/testauthor author-tests --root . --write
```

`scan` returns every policy without a sibling `.test.yaml`, whether it is supported, and the rejection reason for unsupported semantics. `author-tests` previews or writes only the supported subset. Repository owners can review that set in small batches instead of accepting a repository-wide generated change.
