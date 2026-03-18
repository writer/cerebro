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
        payload, _ = self._request_json("POST", f"/api/v1/agent-sdk/tools/{parse.quote(tool_id)}:call", args)
        return payload

    def run_report(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/agent-sdk/report", payload)
        return result

    def get_protected_resource_metadata(self) -> Any:
        result, _ = self._request_json("GET", "/.well-known/oauth-protected-resource")
        return result

    def list_managed_credentials(self) -> Any:
        result, _ = self._request_json("GET", "/api/v1/admin/agent-sdk/credentials")
        return result

    def get_managed_credential(self, credential_id: str) -> Any:
        result, _ = self._request_json("GET", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}")
        return result

    def create_managed_credential(self, payload: Dict[str, Any]) -> Any:
        result, _ = self._request_json("POST", "/api/v1/admin/agent-sdk/credentials", payload)
        return result

    def rotate_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}:rotate", payload or {})
        return result

    def revoke_managed_credential(self, credential_id: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        result, _ = self._request_json("POST", f"/api/v1/admin/agent-sdk/credentials/{parse.quote(credential_id)}:revoke", payload or {})
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


    def annotate(self, args: Any) -> Any:
        return self.call_tool("cerebro_annotate", args)


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


    def entity_history(self, args: Any) -> Any:
        return self.call_tool("cerebro_entity_history", args)


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


    def leverage(self, args: Any) -> Any:
        return self.call_tool("cerebro_leverage", args)


    def observe(self, args: Any) -> Any:
        return self.call_tool("cerebro_observe", args)


    def outcome(self, args: Any) -> Any:
        return self.call_tool("cerebro_outcome", args)


    def quality(self, args: Any) -> Any:
        return self.call_tool("cerebro_quality", args)


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
