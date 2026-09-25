"""Decoy service: an internal-API decoy and an AWS API emulator on one port.

The sensor is deliberately simple (flaw #31): it holds no registry, only forwards what it
sees to control, and shapes its reply from control's answer. Its replies look like the
real thing (flaw #18): no framework banners, no "gotcha", normal 401/403 errors.
"""

from __future__ import annotations

import re
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, unquote

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from .config import Settings
from .forwarder import Forwarder
from .keys import load_keys

_SIGV4 = re.compile(r"Credential=([A-Za-z0-9]{16,128})/(\d{8})/([a-z0-9-]+)/([a-z0-9-]+)/aws4_request")
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def parse_aws_credential(headers, query: dict) -> dict | None:
    auth = headers.get("authorization", "")
    match = _SIGV4.search(auth) if auth.startswith("AWS4-HMAC-SHA256") else None
    if match is None and "X-Amz-Credential" in query:  # presigned URL
        match = _SIGV4.search("Credential=" + unquote(query["X-Amz-Credential"]))
    if match is None:
        return None
    key_id, _date, region, service = match.groups()
    return {"type": "aws", "key_id": key_id, "region": region, "service": service}


def aws_action(service: str, method: str, path: str, body: bytes, headers, query: dict) -> str:
    target = headers.get("x-amz-target")
    if target:
        return f"{service}:{target.rsplit('.', 1)[-1]}"
    params = parse_qs(body.decode("utf-8", "replace")) if body else {}
    action = (params.get("Action") or [query.get("Action")])[0]
    if action:
        return f"{service}:{action}"
    if service == "s3":
        return "s3:ListBuckets" if method == "GET" and path in ("", "/") else f"s3:{method} {path}"
    return f"{service}:{method} {path}"


def parse_api_key(headers, query: dict) -> str | None:
    auth = headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() in ("bearer", "token") and value.strip():
        return value.strip()
    return headers.get("x-api-key") or query.get("api_key") or None


def _request_id() -> str:
    return str(uuid.uuid4())


def _aws_reply(cred: dict, hint: dict | None) -> Response:
    rid = _request_id()
    headers = {"x-amzn-RequestId": rid}
    known = bool(hint and hint.get("known"))
    identity = (hint or {}).get("identity") or {}
    if not known:
        xml = ("<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type>"
               "<Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid."
               f"</Message></Error><RequestId>{rid}</RequestId></ErrorResponse>")
        return Response(xml, status_code=403, media_type="text/xml", headers=headers)
    if cred["action"] == "sts:GetCallerIdentity":
        # A real zero-permission key can always call GetCallerIdentity; answering keeps the attacker engaged.
        xml = ("<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult>"
               f"<Arn>{identity.get('arn', '')}</Arn><UserId>{identity.get('user_id', '')}</UserId>"
               f"<Account>{identity.get('account', '')}</Account></GetCallerIdentityResult>"
               f"<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata></GetCallerIdentityResponse>")
        return Response(xml, status_code=200, media_type="text/xml", headers=headers)
    if cred["service"] == "s3":
        xml = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Access Denied</Message>"
               f"<RequestId>{rid[:16].upper()}</RequestId></Error>")
        return Response(xml, status_code=403, media_type="application/xml", headers=headers)
    action = cred["action"]
    xml = ("<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type>"
           f"<Code>AccessDenied</Code><Message>User: {identity.get('arn', '')} is not authorized to perform: {action} "
           f"because no identity-based policy allows the {action} action</Message></Error>"
           f"<RequestId>{rid}</RequestId></ErrorResponse>")
    return Response(xml, status_code=403, media_type="text/xml", headers=headers)


def _api_reply(hint: dict | None) -> Response:
    rid = _request_id()
    if hint and hint.get("known"):
        body = {"error": "insufficient_scope", "message": "This API key does not have access to the requested resource.", "request_id": rid}
        return JSONResponse(body, status_code=403, headers={"x-request-id": rid})
    body = {"error": "invalid_api_key", "message": "Invalid or expired API key.", "request_id": rid}
    return JSONResponse(body, status_code=401, headers={"x-request-id": rid})


def create_sensor_app(settings: Settings, forwarder: Forwarder | None = None) -> FastAPI:
    forwarder = forwarder or Forwarder(settings, load_keys(settings.key_path), "http-decoy")

    @asynccontextmanager
    async def lifespan(_app):
        forwarder.start_flusher()
        yield
        forwarder.close()

    # No /docs, /redoc or /openapi.json: those would announce "FastAPI" to anyone who looks.
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{full_path:path}", methods=METHODS)
    async def catch_all(request: Request, full_path: str):
        body = await request.body()
        query = dict(request.query_params)
        path = "/" + full_path
        event = {
            "sensor": "http-decoy",
            "kind": "token_use",
            "ts": time.time(),
            "src_ip": request.client.host if request.client else None,
            "src_port": request.client.port if request.client else None,
            "method": request.method,
            "path": path,
            "host_header": request.headers.get("host", ""),
            "user_agent": request.headers.get("user-agent", ""),
        }
        cred = parse_aws_credential(request.headers, query)
        if cred is not None:
            cred["action"] = aws_action(cred["service"], request.method, path, body, request.headers, query)
        else:
            key = parse_api_key(request.headers, query)
            cred = {"type": "api", "key": key, "action": f"{request.method} {path}"} if key else None
        if cred is None:
            return JSONResponse({"error": "unauthorized", "message": "Missing API key."}, status_code=401)
        event["credential"] = cred
        hint = await run_in_threadpool(forwarder.send, event)
        return _aws_reply(cred, hint) if cred["type"] == "aws" else _api_reply(hint)

    return app
