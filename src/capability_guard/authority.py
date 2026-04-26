"""Symmetric MAC capabilities and a transactional local resource boundary."""

from __future__ import annotations

import base64
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time

SCOPES = {"note:read", "note:append", "note:clear"}
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
RESOURCE = re.compile(r"[a-z][a-z0-9_-]{0,31}/[a-z][a-z0-9_-]{0,31}\Z")
TOKEN_ID = re.compile(r"[0-9a-f]{32}\Z")


class AuthorizationError(ValueError):
    """A rejected contract; messages contain no keys, bearer tokens or payloads."""


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizationError("duplicate JSON claim")
        result[key] = value
    return result


@dataclass(frozen=True)
class Claims:
    version: int
    key_id: str
    token_id: str
    issuer: str
    audience: str
    subject: str
    issued_at: int
    expires_at: int
    scopes: tuple[str, ...]
    resources: tuple[str, ...]
    max_calls: int
    max_units: int
    max_bytes: int
    parent_id: str | None = None
    ancestors: tuple[str, ...] = ()

    def validate(self):
        if type(self.version) is not int or self.version != 1:
            raise AuthorizationError("unknown capability version")
        if any(not _identifier(value) for value in (self.key_id, self.issuer, self.audience, self.subject)):
            raise AuthorizationError("invalid capability identity")
        if not isinstance(self.token_id, str) or not TOKEN_ID.fullmatch(self.token_id):
            raise AuthorizationError("invalid capability identifier")
        if (
            not _integer(self.issued_at, 0, 2**63 - 1)
            or not _integer(self.expires_at, 0, 2**63 - 1)
            or not 0 < self.expires_at - self.issued_at <= 86400
        ):
            raise AuthorizationError("expiry must follow issuance by at most one day")
        if (
            not isinstance(self.scopes, tuple)
            or not self.scopes
            or any(not isinstance(value, str) or value not in SCOPES for value in self.scopes)
            or self.scopes != tuple(sorted(set(self.scopes)))
        ):
            raise AuthorizationError("scopes must be a canonical nonempty allowlist")
        if (
            not isinstance(self.resources, tuple)
            or not 1 <= len(self.resources) <= 16
            or any(not isinstance(value, str) or not RESOURCE.fullmatch(value) for value in self.resources)
            or self.resources != tuple(sorted(set(self.resources)))
        ):
            raise AuthorizationError("resources must be a canonical nonempty exact allowlist")
        if (
            not _integer(self.max_calls, 1, 1000)
            or not _integer(self.max_units, 0, 100000)
            or not _integer(self.max_bytes, 0, 4096)
        ):
            raise AuthorizationError("resource budget outside allowed bounds")
        if (
            not isinstance(self.ancestors, tuple)
            or len(self.ancestors) > 8
            or any(not isinstance(value, str) or not TOKEN_ID.fullmatch(value) for value in self.ancestors)
            or len(set(self.ancestors)) != len(self.ancestors)
            or self.token_id in self.ancestors
        ):
            raise AuthorizationError("invalid ancestry")
        if (self.parent_id is None and self.ancestors) or (
            self.parent_id is not None and (not self.ancestors or self.parent_id != self.ancestors[-1])
        ):
            raise AuthorizationError("parent and ancestry disagree")
        return self

    def body(self):
        self.validate()
        return canonical(asdict(self))

    @classmethod
    def decode(cls, body: bytes):
        if len(body) > 8192:
            raise AuthorizationError("claims exceed byte budget")
        try:
            value = json.loads(body, object_pairs_hook=_unique_object)
            if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
                raise AuthorizationError("unknown or missing claim")
            if any(not isinstance(value[key], list) for key in ("scopes", "resources", "ancestors")):
                raise AuthorizationError("claim lists have wrong types")
            for key in ("scopes", "resources", "ancestors"):
                value[key] = tuple(value[key])
            claims = cls(**value).validate()
            if claims.body() != body:
                raise AuthorizationError("claims are not canonical JSON")
            return claims
        except AuthorizationError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as error:
            raise AuthorizationError("invalid claims") from error


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AuthorizationError("invalid token encoding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise AuthorizationError("invalid token encoding") from error
    if _encode(raw) != value:
        raise AuthorizationError("noncanonical token encoding")
    return raw


@dataclass(frozen=True)
class Operation:
    kind: str
    resource: str
    text: str = ""
    limit: int = 256

    def validate(self):
        if (
            not isinstance(self.kind, str)
            or self.kind not in SCOPES
            or not isinstance(self.resource, str)
            or not RESOURCE.fullmatch(self.resource)
        ):
            raise AuthorizationError("tool or resource outside typed contract")
        if not isinstance(self.text, str):
            raise AuthorizationError("tool text must be a UTF-8 string")
        try:
            encoded = self.text.encode("utf-8")
        except UnicodeEncodeError as error:
            raise AuthorizationError("tool text must be valid UTF-8") from error
        if len(encoded) > 4096:
            raise AuthorizationError("tool text exceeds byte budget")
        if self.kind != "note:append" and self.text:
            raise AuthorizationError("only append accepts text")
        if not _integer(self.limit, 0, 4096):
            raise AuthorizationError("read byte limit outside contract")
        return self

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) not in (
            {"kind", "resource"},
            {"kind", "resource", "text"},
            {"kind", "resource", "limit"},
        ):
            raise AuthorizationError("unknown or missing tool field")
        if (
            value.get("kind") == "note:append"
            and set(value) != {"kind", "resource", "text"}
            or value.get("kind") == "note:clear"
            and set(value) != {"kind", "resource"}
            or value.get("kind") == "note:read"
            and "text" in value
        ):
            raise AuthorizationError("tool fields do not match operation kind")
        return cls(**value).validate()


class Authority:
    """Trusted symmetric issuer and local enforcement boundary.

    The caller supplies issuer-owned random keys. Untrusted holders can present
    capabilities and typed requests, but cannot reissue/attenuate credentials.
    """

    def __init__(self, database: str | Path, *, issuer="local-issuer", audience="local-tools", subject="demo-agent"):
        if any(not _identifier(value) for value in (issuer, audience, subject)):
            raise AuthorizationError("invalid authority identity")
        self.database = str(database)
        if self.database == ":memory:":
            raise AuthorizationError("a file-backed SQLite database is required")
        self.issuer, self.audience, self.subject = issuer, audience, subject
        self._keys: dict[str, bytes] = {}
        self._key_lock = threading.RLock()
        self.current_key = None
        with closing(self._connection()) as connection:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS tokens(tid TEXT PRIMARY KEY,body BLOB NOT NULL,kid TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,calls INTEGER NOT NULL DEFAULT 0,units INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS nonces(tid TEXT NOT NULL,nonce TEXT NOT NULL,PRIMARY KEY(tid,nonce));
                CREATE TABLE IF NOT EXISTS notes(resource TEXT PRIMARY KEY,text TEXT NOT NULL);
            """)

    def _connection(self):
        return sqlite3.connect(self.database, timeout=10, isolation_level=None)

    @contextmanager
    def _transaction(self):
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _now(now):
        value = int(time.time()) if now is None else now
        if not _integer(value, 0, 2**63 - 1):
            raise AuthorizationError("trusted clock must supply integer seconds")
        return value

    def add_key(self, key_id: str, key: bytes):
        if not _identifier(key_id) or not isinstance(key, bytes) or len(key) < 32:
            raise AuthorizationError("key ID and at least 32 random key bytes required")
        fingerprint = hashlib.sha256(key).hexdigest()
        with self._key_lock, self._transaction() as connection:
            row = connection.execute("SELECT fingerprint,revoked FROM keys WHERE kid=?", (key_id,)).fetchone()
            if row and (row[0] != fingerprint or row[1]):
                raise AuthorizationError("key identifier cannot be replaced or revived")
            connection.execute("INSERT OR IGNORE INTO keys(kid,fingerprint) VALUES(?,?)", (key_id, fingerprint))
            self._keys[key_id] = bytes(key)
            self.current_key = key_id

    def revoke_key(self, key_id: str):
        with self._transaction() as connection:
            if connection.execute("UPDATE keys SET revoked=1 WHERE kid=?", (key_id,)).rowcount != 1:
                raise AuthorizationError("unknown key")

    def revoke(self, token_id: str):
        with self._transaction() as connection:
            if connection.execute("UPDATE tokens SET revoked=1 WHERE tid=?", (token_id,)).rowcount != 1:
                raise AuthorizationError("unknown capability")

    def verify(self, token: str, *, now=None) -> Claims:
        """Check encoding/MAC/identity/time only, NOT authorization or revocation.

        Only execute() checks registered ancestry, revocation, budgets and nonce
        under the same transaction that applies the local effect.
        """
        current = self._now(now)
        if not isinstance(token, str) or len(token) > 12000 or token.count(".") != 1:
            raise AuthorizationError("invalid bearer token")
        encoded_body, encoded_mac = token.split(".")
        body, mac = _decode(encoded_body), _decode(encoded_mac)
        claims = Claims.decode(body)
        with self._key_lock:
            key = self._keys.get(claims.key_id)
            if key is None or len(mac) != 32 or not hmac.compare_digest(hmac.digest(key, body, "sha256"), mac):
                raise AuthorizationError("invalid MAC")
        if (claims.issuer, claims.audience, claims.subject) != (self.issuer, self.audience, self.subject):
            raise AuthorizationError("issuer, audience or subject mismatch")
        if not claims.issued_at <= current < claims.expires_at:
            raise AuthorizationError("capability is expired or not yet active")
        return claims

    def _register(self, claims: Claims):
        body = claims.body()
        with self._transaction() as connection:
            key = connection.execute("SELECT revoked FROM keys WHERE kid=?", (claims.key_id,)).fetchone()
            if not key or key[0]:
                raise AuthorizationError("issuing key is revoked")
            self._check_chain(connection, claims, claims.issued_at, include_self=False)
            connection.execute("INSERT INTO tokens(tid,body,kid) VALUES(?,?,?)", (claims.token_id, body, claims.key_id))
        with self._key_lock:
            return _encode(body) + "." + _encode(hmac.digest(self._keys[claims.key_id], body, "sha256"))

    def issue(self, *, scopes, resources, max_calls=10, max_units=1024, max_bytes=256, ttl=60, now=None):
        current = self._now(now)
        if type(ttl) is not int:
            raise AuthorizationError("TTL must be an integer")
        with self._key_lock:
            key_id = self.current_key
        if key_id is None:
            raise AuthorizationError("no issuing key")
        claims = Claims(
            1,
            key_id,
            secrets.token_hex(16),
            self.issuer,
            self.audience,
            self.subject,
            current,
            current + ttl,
            tuple(sorted(scopes)),
            tuple(sorted(resources)),
            max_calls,
            max_units,
            max_bytes,
        )
        return self._register(claims)

    def attenuate(
        self,
        parent_token: str,
        *,
        scopes=None,
        resources=None,
        max_calls=None,
        max_units=None,
        max_bytes=None,
        expires_at=None,
        now=None,
    ):
        current = self._now(now)
        parent = self.verify(parent_token, now=current)
        changes = {
            "scopes": tuple(sorted(scopes)) if scopes is not None else parent.scopes,
            "resources": tuple(sorted(resources)) if resources is not None else parent.resources,
            "max_calls": parent.max_calls if max_calls is None else max_calls,
            "max_units": parent.max_units if max_units is None else max_units,
            "max_bytes": parent.max_bytes if max_bytes is None else max_bytes,
            "expires_at": parent.expires_at if expires_at is None else expires_at,
        }
        if not set(changes["scopes"]) <= set(parent.scopes) or not set(changes["resources"]) <= set(parent.resources):
            raise AuthorizationError("attenuation cannot widen allowlists")
        for field in ("max_calls", "max_units", "max_bytes", "expires_at"):
            if type(changes[field]) is not int or changes[field] > getattr(parent, field):
                raise AuthorizationError("attenuation cannot widen budgets or lifetime")
        with self._key_lock:
            key_id = self.current_key
        claims = Claims(
            1,
            key_id,
            secrets.token_hex(16),
            self.issuer,
            self.audience,
            self.subject,
            current,
            changes["expires_at"],
            changes["scopes"],
            changes["resources"],
            changes["max_calls"],
            changes["max_units"],
            changes["max_bytes"],
            parent.token_id,
            parent.ancestors + (parent.token_id,),
        )
        return self._register(claims)

    def _check_chain(self, connection, claims, now, *, include_self=True):
        chain = []
        for index, token_id in enumerate(claims.ancestors + ((claims.token_id,) if include_self else ())):
            row = connection.execute(
                "SELECT t.body,t.revoked,t.calls,t.units,k.revoked FROM tokens t JOIN keys k ON k.kid=t.kid WHERE tid=?",
                (token_id,),
            ).fetchone()
            if not row or row[1] or row[4]:
                raise AuthorizationError("capability or ancestor/key revoked or unregistered")
            stored = Claims.decode(row[0])
            if stored.ancestors != claims.ancestors[:index] or not stored.issued_at <= now < stored.expires_at:
                raise AuthorizationError("invalid or expired delegation chain")
            if stored.token_id == claims.token_id and stored.body() != claims.body():
                raise AuthorizationError("registered claims do not match bearer")
            chain.append((stored, row[2], row[3]))
        return chain

    def execute(self, token: str, operation: Operation, *, nonce: str, now=None):
        current = self._now(now)
        claims = self.verify(token, now=current)
        if not isinstance(operation, Operation):
            raise AuthorizationError("typed operation required")
        operation.validate()
        if not isinstance(nonce, str) or not TOKEN_ID.fullmatch(nonce):
            raise AuthorizationError("nonce must be 128-bit lowercase hexadecimal")
        if operation.kind not in claims.scopes or operation.resource not in claims.resources:
            raise AuthorizationError("tool or resource not authorized")
        with self._transaction() as connection:
            chain = self._check_chain(connection, claims, self._now(now))
            row = connection.execute("SELECT text FROM notes WHERE resource=?", (operation.resource,)).fetchone()
            existing = row[0] if row else ""
            if operation.kind == "note:read":
                text = existing.encode("utf-8")[: operation.limit].decode("utf-8", errors="ignore")
                units = len(text.encode("utf-8"))
            else:
                text = operation.text
                units = len(text.encode("utf-8"))
            for ancestor, calls, used in chain:
                if (
                    operation.kind not in ancestor.scopes
                    or operation.resource not in ancestor.resources
                    or units > ancestor.max_bytes
                    or (operation.kind == "note:read" and operation.limit > ancestor.max_bytes)
                ):
                    raise AuthorizationError("ancestor restricts operation")
                if calls + 1 > ancestor.max_calls or used + units > ancestor.max_units:
                    raise AuthorizationError("shared capability quota exhausted")
            if operation.kind == "note:append" and len(existing.encode("utf-8")) + units > 1_000_000:
                raise AuthorizationError("local resource size limit exceeded")
            try:
                connection.execute("INSERT INTO nonces VALUES(?,?)", (claims.token_id, nonce))
            except sqlite3.IntegrityError as error:
                raise AuthorizationError("nonce already committed") from error
            for ancestor, _, _ in chain:
                connection.execute(
                    "UPDATE tokens SET calls=calls+1,units=units+? WHERE tid=?", (units, ancestor.token_id)
                )
            if operation.kind == "note:append":
                connection.execute(
                    "INSERT INTO notes VALUES(?,?) ON CONFLICT(resource) DO UPDATE SET text=text||excluded.text",
                    (operation.resource, text),
                )
                result = {"appended_bytes": units, "resource_bytes": len(existing.encode("utf-8")) + units}
            elif operation.kind == "note:clear":
                connection.execute("DELETE FROM notes WHERE resource=?", (operation.resource,))
                result = {"cleared": bool(row)}
            else:
                result = {"text": text, "returned_bytes": units}
            return {"committed": True, "operation": operation.kind, "resource": operation.resource, "result": result}

    def usage(self, token_id: str):
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT calls,units,revoked FROM tokens WHERE tid=?", (token_id,)).fetchone()
            if not row:
                raise AuthorizationError("unknown capability")
            return {"calls": row[0], "units": row[1], "revoked": bool(row[2])}
