import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib import error, parse, request


class APIError(Exception):
    def __init__(self, status_code: int, message: str, code: str = "") -> None:
        super().__init__(f"api request failed ({status_code}{' ' + code if code else ''}): {message}")
        self.status_code = status_code
        self.message = message
        self.code = code


@dataclass
class Client:
    base_url: str
    api_key: Optional[str] = None
    timeout: float = 15.0
    user_agent: str = "cerebro-sdk-python"

    def put_source_runtime(self, runtime_id: str, runtime: Dict[str, Any]) -> Any:
        result, _ = self._request_json("PUT", f"/source-runtimes/{parse.quote(runtime_id, safe='')}", {"runtime": runtime})
        return result

    def get_source_runtime(self, runtime_id: str) -> Any:
        result, _ = self._request_json("GET", f"/source-runtimes/{parse.quote(runtime_id, safe='')}")
        return result

    def list_source_runtimes(self, filters: Optional[Dict[str, Any]] = None) -> Any:
        query = _query_params(filters or {})
        path = "/source-runtimes"
        if query:
            path = f"{path}?{parse.urlencode(query)}"
        result, _ = self._request_json("GET", path)
        return result

    def write_claims(
        self,
        runtime_id: str,
        claims: list[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        payload: Dict[str, Any] = dict(options or {})
        payload["claims"] = claims
        result, _ = self._request_json("POST", f"/source-runtimes/{parse.quote(runtime_id, safe='')}/claims", payload)
        return result

    def list_claims(self, runtime_id: str, filters: Optional[Dict[str, Any]] = None) -> Any:
        query: Dict[str, str] = {}
        for key, value in (filters or {}).items():
            if value in (None, ""):
                continue
            query[key] = str(value)
        path = f"/source-runtimes/{parse.quote(runtime_id, safe='')}/claims"
        if query:
            path = f"{path}?{parse.urlencode(query)}"
        result, _ = self._request_json("GET", path)
        return result

    def get_entity_neighborhood(self, root_urn: str, limit: int = 0) -> Any:
        normalized_root_urn = root_urn.strip()
        if not normalized_root_urn:
            raise ValueError("root_urn is required")
        query = {"root_urn": normalized_root_urn}
        if limit > 0:
            query["limit"] = str(limit)
        result, _ = self._request_json("GET", f"/platform/graph/neighborhood?{parse.urlencode(query)}")
        return result

    def create_job(self, payload: Dict[str, Any], idempotency_key: str = "") -> Any:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        result, _ = self._request_json("POST", "/platform/jobs", payload, headers)
        return result

    def list_jobs(self, filters: Optional[Dict[str, Any]] = None) -> Any:
        query: Dict[str, str] = {}
        for key, value in (filters or {}).items():
            if value in (None, ""):
                continue
            query[key] = str(value)
        path = "/platform/jobs"
        if query:
            path = f"{path}?{parse.urlencode(query)}"
        result, _ = self._request_json("GET", path)
        return result

    def get_job(self, job_id: str) -> Any:
        result, _ = self._request_json("GET", f"/platform/jobs/{parse.quote(job_id, safe='')}")
        return result

    def list_job_events(self, job_id: str, limit: int = 0) -> Any:
        path = f"/platform/jobs/{parse.quote(job_id, safe='')}/events"
        if limit > 0:
            path = f"{path}?{parse.urlencode({'limit': str(limit)})}"
        result, _ = self._request_json("GET", path)
        return result

    def cancel_job(self, job_id: str) -> Any:
        result, _ = self._request_json("POST", f"/platform/jobs/{parse.quote(job_id, safe='')}/cancel")
        return result

    def integration(self, runtime_id: str, tenant_id: str, integration: str) -> "IntegrationClient":
        return IntegrationClient(self, runtime_id=runtime_id, tenant_id=tenant_id, integration=integration)

    def _request_json(self, method: str, path: str, body: Optional[Any] = None, headers: Optional[Dict[str, str]] = None):
        response = self._request_raw(method, path, body, headers or {})
        try:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else None, dict(response.headers)
        finally:
            response.close()

    def _request_raw(self, method: str, path: str, body: Optional[Any], headers: Dict[str, str]):
        url = self.base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
        headers.setdefault("User-Agent", self.user_agent)
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            return request.urlopen(req, timeout=self.timeout)
        except error.HTTPError as exc:
            payload = exc.read().decode("utf-8")
            try:
                decoded = json.loads(payload)
                raise APIError(exc.code, decoded.get("error", payload), decoded.get("code", "")) from exc
            except json.JSONDecodeError:
                raise APIError(exc.code, payload or exc.reason, "") from exc


def _query_params(filters: Dict[str, Any]) -> Dict[str, str]:
    query: Dict[str, str] = {}
    for key, value in filters.items():
        if value in (None, ""):
            continue
        if isinstance(value, (list, tuple)):
            parts = [str(item) for item in value if item not in (None, "")]
            if parts:
                query[key] = ",".join(parts)
            continue
        query[key] = str(value)
    return query


@dataclass
class IntegrationClient:
    client: Client
    runtime_id: str
    tenant_id: str
    integration: str

    def ensure_runtime(self, config: Optional[Dict[str, str]] = None) -> Any:
        if config is None:
            config = {}
        runtime = {
            "source_id": "sdk",
            "tenant_id": self.tenant_id,
            "config": {
                "integration": self.integration,
                **config,
            },
        }
        return self.client.put_source_runtime(self.runtime_id, runtime)

    def write_claims(self, claims: list[Dict[str, Any]], options: Optional[Dict[str, Any]] = None) -> Any:
        return self.client.write_claims(self.runtime_id, claims, options)

    def list_claims(self, filters: Optional[Dict[str, Any]] = None) -> Any:
        return self.client.list_claims(self.runtime_id, filters)

    def graph_neighborhood(self, root: Any, limit: int = 0) -> Any:
        if isinstance(root, dict):
            root_urn = str(root["urn"]).strip()
        else:
            root_urn = str(root).strip()
        return self.client.get_entity_neighborhood(root_urn, limit)

    def graph_layering(self, roots: list[Any], limit: int = 0) -> Dict[str, Any]:
        layering: Dict[str, Any] = {}
        seen = set()
        for root in roots:
            if isinstance(root, dict):
                root_urn = str(root["urn"]).strip()
            else:
                root_urn = str(root).strip()
            if not root_urn or root_urn in seen:
                continue
            seen.add(root_urn)
            try:
                layering[root_urn] = self.graph_neighborhood(root_urn, limit)
            except APIError as err:
                layering[root_urn] = {
                    "root_urn": root_urn,
                    "error": str(err),
                }
        return layering

    def graph_summary(self, layering: Dict[str, Any]) -> Dict[str, Any]:
        roots = []
        node_counts: Dict[str, int] = {}
        relation_counts: Dict[str, int] = {}
        neighborhood_sizes: Dict[str, Dict[str, int]] = {}
        errors: Dict[str, str] = {}
        seen_nodes = set()
        seen_relations = set()
        for root_urn, entry in layering.items():
            if not isinstance(entry, dict):
                continue
            error = _optional_string(entry.get("error"))
            if error is not None:
                errors[_optional_string(entry.get("root_urn")) or root_urn] = error
                continue
            root = entry.get("root")
            if not isinstance(root, dict):
                continue
            root_key = _optional_string(root.get("urn"))
            if root_key is None:
                continue
            roots.append(
                {
                    "urn": root_key,
                    "entity_type": _optional_string(root.get("entity_type")) or "unknown",
                    "label": _optional_string(root.get("label")) or root_key,
                }
            )
            neighbors = entry.get("neighbors")
            if not isinstance(neighbors, list):
                neighbors = []
            relations = entry.get("relations")
            if not isinstance(relations, list):
                relations = []
            neighborhood_sizes[root_key] = {
                "neighbors": len(neighbors),
                "relations": len(relations),
            }
            for node in [root] + neighbors:
                if not isinstance(node, dict):
                    continue
                node_urn = _optional_string(node.get("urn"))
                entity_type = _optional_string(node.get("entity_type")) or "unknown"
                if node_urn is None or node_urn in seen_nodes:
                    continue
                seen_nodes.add(node_urn)
                node_counts[entity_type] = node_counts.get(entity_type, 0) + 1
            for relation in relations:
                if not isinstance(relation, dict):
                    continue
                from_urn = _optional_string(relation.get("from_urn"))
                name = _optional_string(relation.get("relation"))
                to_urn = _optional_string(relation.get("to_urn"))
                if from_urn is None or name is None or to_urn is None:
                    continue
                key = (from_urn, name, to_urn)
                if key in seen_relations:
                    continue
                seen_relations.add(key)
                relation_counts[name] = relation_counts.get(name, 0) + 1
        return {
            "roots": roots,
            "node_counts_by_type": node_counts,
            "relation_counts_by_type": relation_counts,
            "neighborhood_sizes": neighborhood_sizes,
            "errors": errors,
        }

    def ref(self, kind: str, external_id: str, label: str = "") -> Dict[str, str]:
        normalized_kind = kind.strip()
        normalized_external_id = external_id.strip()
        if not normalized_kind:
            raise ValueError("kind is required")
        if not normalized_external_id:
            raise ValueError("external_id is required")
        return {
            "urn": self._build_urn(normalized_kind, normalized_external_id),
            "entity_type": normalized_kind,
            "label": label.strip() or normalized_external_id,
        }

    def exists(self, subject: Dict[str, str], **options: Any) -> Dict[str, Any]:
        return self._build_claim(subject, "exists", claim_type=options.pop("claim_type", "existence"), **options)

    def attr(self, subject: Dict[str, str], predicate: str, value: str, **options: Any) -> Dict[str, Any]:
        return self._build_claim(
            subject,
            predicate,
            claim_type=options.pop("claim_type", "attribute"),
            object_value=value.strip(),
            **options,
        )

    def rel(self, subject: Dict[str, str], predicate: str, obj: Dict[str, str], **options: Any) -> Dict[str, Any]:
        return self._build_claim(
            subject,
            predicate,
            claim_type=options.pop("claim_type", "relation"),
            object_ref=obj,
            object_urn=obj["urn"],
            **options,
        )

    def _build_claim(self, subject: Dict[str, str], predicate: str, **options: Any) -> Dict[str, Any]:
        subject_urn = subject["urn"].strip()
        normalized_predicate = predicate.strip()
        if not subject_urn:
            raise ValueError("subject['urn'] is required")
        if not normalized_predicate:
            raise ValueError("predicate is required")
        claim = {
            "subject_urn": subject_urn,
            "subject_ref": subject,
            "predicate": normalized_predicate,
        }
        claim.update({key: value for key, value in options.items() if value not in (None, "")})
        return claim

    def _build_urn(self, kind: str, external_id: str) -> str:
        return ":".join(["urn", "cerebro", self.tenant_id, "runtime", self.runtime_id, kind, external_id])


def _optional_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
