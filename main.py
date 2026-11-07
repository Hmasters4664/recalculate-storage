"""
Recalculate storage — sets teams.storageUsed from the files table.

RULE (shared with delete-file): storageUsed = total `size` of the team's files
that are NOT in the recycle bin, in MB (2 decimals). Old versions and files in
the bin are not counted. The value is SET, not adjusted, so running this
repeatedly is safe and corrects drift from any source.

Triggers
  POST {"teamId": "..."}                      recalculate one team
                                              (confirmed owner/admin/editor).
                                              The app executes it ASYNC (no 30 s
                                              sync limit) and reads storageUsed
                                              back; the response body is for
                                              console/sync callers only.
  POST {"teamId": "...", "includeB2": true}   also report actual B2 usage under
                                              "<teamId>/" (owner/admin only;
                                              report only, never written)
  schedule (x-appwrite-trigger: schedule)     recalculate every team

Env:    optional DATABASE_ID; for includeB2: B2_KEY_ID, B2_APP_KEY, B2_BUCKET_ID
        (key needs listFiles)
Scopes: users.read, rows/documents read + write
"""
import json
import os
import re
import time

import requests
from appwrite.client import Client
from appwrite.query import Query
from appwrite.services.account import Account
from appwrite.services.databases import Databases
from appwrite.services.users import Users

DATABASE_ID = os.environ.get("DATABASE_ID", "66c0c189002c3b8eb3ea")
FILES = "files"
TEAMS = "teams"
# Rows per page. Only $id and size are fetched, so large pages stay small.
PAGE = 500
EDIT_ROLES = {"owner", "admin", "editor"}
AUDIT_ROLES = {"owner", "admin"}
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,36}$")
MB = 1024 * 1024


def _as_dict(obj):
    """
    Normalises an SDK response to Appwrite's own JSON field names.

    Older Python SDKs return dicts. Newer ones (27.x) return pydantic models that
    rename fields (teamId -> teamid, $id -> id) and keep a row's own columns in
    .data, so attribute access by the API name silently returns nothing.
    to_dict() restores the API names; a row's "data" is merged back to the top.
    """
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        to_dict = getattr(obj, "to_dict", None)
        obj = to_dict() if callable(to_dict) else {}
    nested = obj.get("data")
    if isinstance(nested, dict):
        return {**nested, **{k: v for k, v in obj.items() if k != "data"}}
    return obj


def _field(obj, key):
    """Reads a field by its Appwrite API name, whatever the SDK version returned."""
    return _as_dict(obj).get(key)


def _fail(res, status, code, message):
    return res.json({"error": code, "message": message}, status)


def _parse_body(req):
    body = req.body
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8")
    if isinstance(body, str):
        return json.loads(body) if body.strip() else {}
    return body or {}


def _pages(db, collection, queries, columns):
    """
    Yields every row matching `queries`, using cursor pagination.

    total=False skips Appwrite's row count, which otherwise runs on every page
    and dominates the time on large tables. Only `columns` are fetched.
    """
    cursor = None
    while True:
        page_queries = [*queries, Query.select(["$id", *columns]), Query.limit(PAGE)]
        if cursor:
            page_queries.append(Query.cursor_after(cursor))
        try:
            result = db.list_documents(database_id=DATABASE_ID, collection_id=collection, queries=page_queries, total=False)
        except TypeError:  # SDK older than the pinned one: no `total` parameter
            result = db.list_documents(database_id=DATABASE_ID, collection_id=collection, queries=page_queries)
        rows = _field(result, "documents") or []
        yield from rows
        if len(rows) < PAGE:
            return
        cursor = _field(rows[-1], "$id")


def recalculate_team(db, team_id):
    """Sums live file sizes for one team and writes storageUsed. Returns a summary."""
    total_bytes, files, missing_size = 0, 0, 0
    for row in _pages(db, FILES, [Query.equal("teamId", team_id), Query.equal("deleted", False)], ["size"]):
        files += 1
        size = _field(row, "size")  # bytes; a number, or a string in some older rows
        try:
            total_bytes += int(float(size))
        except (TypeError, ValueError):
            missing_size += 1  # None, "" or unparsable: counted as 0 and reported

    team = db.get_document(database_id=DATABASE_ID, collection_id=TEAMS, document_id=team_id)
    previous = float(_field(team, "storageUsed") or 0)
    used_mb = round(total_bytes / MB, 2)
    if used_mb != previous:
        db.update_document(database_id=DATABASE_ID, collection_id=TEAMS, document_id=team_id, data={"storageUsed": used_mb})

    return {
        "teamId": team_id,
        "storageUsedMB": used_mb,
        "previousMB": previous,
        "driftMB": round(used_mb - previous, 2),
        "liveFiles": files,
        "filesWithoutSize": missing_size,
        "storageLimitMB": _field(team, "storageLimit"),
    }


def b2_audit(team_id):
    """Actual B2 usage under "<teamId>/": every stored version, including bin and old versions."""
    auth = requests.get(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
        auth=(os.environ["B2_KEY_ID"], os.environ["B2_APP_KEY"]),
        timeout=15,
    )
    auth.raise_for_status()
    auth = auth.json()

    prefix = f"{team_id}/"
    total_bytes, versions, names = 0, 0, set()
    start_name, start_id = None, None
    deadline = time.time() + 240  # leave headroom inside the function timeout
    while True:
        payload = {"bucketId": os.environ["B2_BUCKET_ID"], "prefix": prefix, "maxFileCount": 1000}
        if start_name:
            payload.update(startFileName=start_name, startFileId=start_id)
        res = requests.post(
            f"{auth['apiUrl']}/b2api/v2/b2_list_file_versions",
            headers={"Authorization": auth["authorizationToken"]},
            json=payload,
            timeout=30,
        )
        res.raise_for_status()
        data = res.json()
        for f in data.get("files", []):
            if f.get("action") != "upload":
                continue  # hide markers and unfinished large files hold no bytes
            total_bytes += int(f.get("contentLength") or 0)
            versions += 1
            names.add(f.get("fileName"))
        start_name, start_id = data.get("nextFileName"), data.get("nextFileId")
        if not start_name:
            return {"b2MB": round(total_bytes / MB, 2), "b2Versions": versions, "b2Objects": len(names), "complete": True}
        if time.time() > deadline:
            return {"b2MB": round(total_bytes / MB, 2), "b2Versions": versions, "b2Objects": len(names), "complete": False}


def _scheduled(context, db):
    done, failed, drift = 0, 0, 0.0
    for team in _pages(db, TEAMS, [], []):
        team_id = _field(team, "$id")
        try:
            summary = recalculate_team(db, team_id)
            done += 1
            drift += abs(summary["driftMB"])
            if summary["driftMB"]:
                context.log(f"team {team_id}: {summary['previousMB']} -> {summary['storageUsedMB']} MB")
        except Exception as e:
            failed += 1
            context.error(f"team {team_id}: {e}")
    context.log(f"scheduled recalculation: {done} teams, {failed} failed, {round(drift, 2)} MB total drift corrected")
    return context.res.json({"ok": True, "teams": done, "failed": failed}, 200)


def main(context):
    req, res = context.req, context.res
    endpoint = os.environ["APPWRITE_FUNCTION_API_ENDPOINT"]
    project_id = os.environ["APPWRITE_FUNCTION_PROJECT_ID"]

    server = Client()
    server.set_endpoint(endpoint)
    server.set_project(project_id)
    server.set_key(req.headers.get("x-appwrite-key"))
    db = Databases(server)

    if req.headers.get("x-appwrite-trigger") == "schedule":
        return _scheduled(context, db)

    if req.method == "OPTIONS":
        return res.send("", 204)
    if req.method != "POST":
        return _fail(res, 405, "method_not_allowed", "Use POST.")

    # Caller: from Appwrite's headers, verified via the JWT.
    user_id = req.headers.get("x-appwrite-user-id")
    user_jwt = req.headers.get("x-appwrite-user-jwt")
    if not user_id or not user_jwt:
        return _fail(res, 401, "unauthenticated", "Sign in to continue.")
    try:
        user_client = Client()
        user_client.set_endpoint(endpoint)
        user_client.set_project(project_id)
        user_client.set_jwt(user_jwt)
        if _field(Account(user_client).get(), "$id") != user_id:
            return _fail(res, 401, "unauthenticated", "Session does not match.")
    except Exception:
        return _fail(res, 401, "unauthenticated", "Session is invalid or expired.")

    try:
        body = _parse_body(req)
    except (ValueError, UnicodeDecodeError):
        return _fail(res, 400, "invalid_json", "Request body must be JSON.")
    team_id = body.get("teamId")
    if not isinstance(team_id, str) or not ID_RE.match(team_id):
        return _fail(res, 400, "invalid_team", "Invalid team id.")

    try:
        result = Users(server).list_memberships(user_id=user_id, queries=[Query.equal("teamId", team_id)])
        membership = next(
            (m for m in (_field(result, "memberships") or [])
             if _field(m, "teamId") == team_id and _field(m, "confirm")),
            None,
        )
    except Exception as e:
        context.error(f"membership lookup failed: {e}")
        return _fail(res, 502, "membership_lookup_failed", "Could not verify team membership.")
    if membership is None:
        return _fail(res, 403, "not_a_member", "You are not a member of this team.")
    roles = set(_field(membership, "roles") or [])
    if not roles & EDIT_ROLES:
        return _fail(res, 403, "forbidden", "Your role in this team can't recalculate storage.")
    if body.get("includeB2") and not roles & AUDIT_ROLES:
        return _fail(res, 403, "forbidden", "Only owners and admins can run the B2 audit.")

    started = time.time()
    try:
        summary = recalculate_team(db, team_id)
    except Exception as e:
        context.error(f"recalculate {team_id}: {e}")
        return _fail(res, 500, "failed", "Couldn't recalculate storage. Please try again.")

    if body.get("includeB2"):
        try:
            summary["b2"] = b2_audit(team_id)
        except Exception as e:
            context.error(f"b2 audit {team_id}: {e}")
            summary["b2"] = {"error": "B2 audit failed; see function logs."}
        # The app runs this function asynchronously, which discards the response
        # body, so the audit result is only visible in the execution log.
        context.log(f"b2 audit team={team_id}: {summary['b2']}")

    context.log(f"recalculated team={team_id} user={user_id} {summary['previousMB']} -> {summary['storageUsedMB']} MB "
                f"({summary['liveFiles']} files, {round(time.time() - started, 1)}s)")
    return res.json({"ok": True, **summary}, 200)
