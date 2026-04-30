import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
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

    def list_tools(self) -> Any:
        payload, _ = self._request_json("GET", "/api/v1/agent-sdk/tools")
        return payload

    def call_tool(self, tool_id: str, args: Any) -> Any:
        payload, _ = self._request_json("POST", f"/api/v1/agent-sdk/tools/{parse.quote(tool_id, safe='')}:call", args)
        return payload

    def run_report(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/agent-sdk/report", payload)
        return result

    def get_protected_resource_metadata(self) -> Any:
        result, _ = self._request_json("GET", "/.well-known/oauth-protected-resource")
        return result

    def put_source_runtime(self, runtime_id: str, runtime: Dict[str, Any]) -> Any:
        result, _ = self._request_json("PUT", f"/source-runtimes/{parse.quote(runtime_id, safe='')}", {"runtime": runtime})
        return result

    def get_source_runtime(self, runtime_id: str) -> Any:
        result, _ = self._request_json("GET", f"/source-runtimes/{parse.quote(runtime_id, safe='')}")
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
        result, _ = self._request_json("GET", f"/graph/neighborhood?{parse.urlencode(query)}")
        return result

    def integration(self, runtime_id: str, tenant_id: str, integration: str) -> "IntegrationClient":
        return IntegrationClient(self, runtime_id=runtime_id, tenant_id=tenant_id, integration=integration)

    def list_managed_credentials(self) -> Any:
        result, _ = self._request_json("GET", "/api/v1/admin/agent-sdk/credentials")
        return result

    def get_managed_credential(self, credential_id: str) -> Any:
        result, _ = self._request_json("GET", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id, safe='')}")
        return result

    def create_managed_credential(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/admin/agent-sdk/credentials", payload)
        return result

    def rotate_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id, safe='')}:rotate", payload or {})
        return result

    def revoke_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id, safe='')}:revoke", payload or {})
        return result

    def mcp(self, payload: Dict[str, Any], session_id: str = "") -> Tuple[Any, str]:
        headers = {}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        response, response_headers = self._request_json("POST", "/api/v1/mcp", payload, headers)
        return response, response_headers.get("Mcp-Session-Id", "")

    def open_mcp_stream(self, session_id: str = ""):
        headers = {"Accept": "text/event-stream"}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return self._request_raw("GET", "/api/v1/mcp", None, headers)

    def open_report_run_stream(self, status_path: str):
        return self._request_raw("GET", f"{status_path}/stream", None, {"Accept": "text/event-stream"})


    def access_review(self, args: Any) -> Any:
        return self.call_tool("cerebro_access_review", args)


    def actuate_recommendation(self, args: Any) -> Any:
        return self.call_tool("cerebro_actuate_recommendation", args)


    def ai_workloads(self, args: Any) -> Any:
        return self.call_tool("cerebro_ai_workloads", args)


    def annotate(self, args: Any) -> Any:
        return self.call_tool("cerebro_annotate", args)


    def autonomous_credential_response(self, args: Any) -> Any:
        return self.call_tool("cerebro_autonomous_credential_response", args)


    def autonomous_workflow_approve(self, args: Any) -> Any:
        return self.call_tool("cerebro_autonomous_workflow_approve", args)


    def autonomous_workflow_status(self, args: Any) -> Any:
        return self.call_tool("cerebro_autonomous_workflow_status", args)


    def blast_radius(self, args: Any) -> Any:
        return self.call_tool("cerebro_blast_radius", args)


    def check(self, args: Any) -> Any:
        return self.call_tool("cerebro_check", args)


    def claim(self, args: Any) -> Any:
        return self.call_tool("cerebro_claim", args)


    def context(self, args: Any) -> Any:
        return self.call_tool("cerebro_context", args)


    def correlate_events(self, args: Any) -> Any:
        return self.call_tool("cerebro_correlate_events", args)


    def decide(self, args: Any) -> Any:
        return self.call_tool("cerebro_decide", args)


    def diff(self, args: Any) -> Any:
        return self.call_tool("cerebro_diff", args)


    def entity_history(self, args: Any) -> Any:
        return self.call_tool("cerebro_entity_history", args)


    def execution_status(self, args: Any) -> Any:
        return self.call_tool("cerebro_execution_status", args)


    def findings(self, args: Any) -> Any:
        return self.call_tool("cerebro_findings", args)


    def graph_changelog(self, args: Any) -> Any:
        return self.call_tool("cerebro_graph_changelog", args)


    def graph_query(self, args: Any) -> Any:
        return self.call_tool("cerebro_graph_query", args)


    def graph_simulate(self, args: Any) -> Any:
        return self.call_tool("cerebro_graph_simulate", args)


    def identity_calibration(self, args: Any) -> Any:
        return self.call_tool("cerebro_identity_calibration", args)


    def identity_review(self, args: Any) -> Any:
        return self.call_tool("cerebro_identity_review", args)


    def key_person_risk(self, args: Any) -> Any:
        return self.call_tool("cerebro_key_person_risk", args)


    def leverage(self, args: Any) -> Any:
        return self.call_tool("cerebro_leverage", args)


    def nlq(self, args: Any) -> Any:
        return self.call_tool("cerebro_nlq", args)


    def observe(self, args: Any) -> Any:
        return self.call_tool("cerebro_observe", args)


    def outcome(self, args: Any) -> Any:
        return self.call_tool("cerebro_outcome", args)


    def quality(self, args: Any) -> Any:
        return self.call_tool("cerebro_quality", args)


    def reconstruct(self, args: Any) -> Any:
        return self.call_tool("cerebro_reconstruct", args)


    def report(self, args: Any) -> Any:
        return self.call_tool("cerebro_report", args)


    def resolve_identity(self, args: Any) -> Any:
        return self.call_tool("cerebro_resolve_identity", args)


    def risk_score(self, args: Any) -> Any:
        return self.call_tool("cerebro_risk_score", args)


    def simulate(self, args: Any) -> Any:
        return self.call_tool("cerebro_simulate", args)


    def split_identity(self, args: Any) -> Any:
        return self.call_tool("cerebro_split_identity", args)


    def templates(self, args: Any) -> Any:
        return self.call_tool("cerebro_templates", args)


    def timeline(self, args: Any) -> Any:
        return self.call_tool("cerebro_timeline", args)


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
