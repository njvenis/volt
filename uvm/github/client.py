"""Small credential-safe GitHub REST client for the local G4 POC."""

from __future__ import annotations

import json
import ipaddress
import os
import stat
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import Request, urlopen


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, *, body=None):
        super().__init__(message)
        self.status = status
        self.body = body


class GitHubOutcomeUnknown(RuntimeError):
    """Transport ended without establishing whether an external write applied."""


class GitHubREST:
    def __init__(self, *, token_file: str | None = None, github_host="github.com",
                 timeout=30, token: str | None = None, before_request=None,
                 app_bot_login: str | None = None):
        if github_host != "github.com":
            raise ValueError("the G4 local POC currently supports github.com only")
        path = token_file or (os.environ.get("UVM_GITHUB_TOKEN_FILE") if token is None else None)
        if token is None and not path:
            raise RuntimeError("GitHub credentials are not configured")
        if token is None:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode != 0o600:
                raise RuntimeError("GitHub token file must have mode 0600")
            token = Path(path).read_text(encoding="ascii").strip()
        self.token = token
        if not self.token or any(ch.isspace() for ch in self.token):
            raise RuntimeError("GitHub token file is empty or invalid")
        configured_base = os.environ.get("UVM_GITHUB_API_BASE_URL")
        if configured_base:
            parsed = urlparse(configured_base)
            disposable = os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1"
            try:
                loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
            except ValueError:
                loopback = parsed.hostname == "localhost"
            if (not disposable or parsed.scheme != "http" or not loopback
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")):
                raise ValueError("custom GitHub API origin is permitted only for loopback disposable mode")
            self.base = configured_base.rstrip("/") + "/"
        else:
            self.base = "https://api.github.com/"
        self.origin = urlparse(self.base).netloc
        self.timeout = timeout
        self.before_request = before_request
        self.app_bot_login = app_bot_login

    def _path(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            if parsed.netloc != self.origin or parsed.scheme != urlparse(self.base).scheme:
                raise ValueError("pagination link escaped configured GitHub API origin")
            return path
        return urljoin(self.base, path.lstrip("/"))

    def request(self, method: str, path: str, body=None, headers=None):
        lease = self.before_request(method.upper(), path) if self.before_request is not None else None
        try:
            url = self._path(path)
            payload = None if body is None else json.dumps(body, sort_keys=True,
                separators=(",", ":")).encode()
            request = Request(url, data=payload, method=method.upper(), headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "UVM-G4-local-proof",
                **(headers or {}),
                **({"Content-Type": "application/json"} if payload is not None else {}),
            })
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                result = json.loads(raw) if raw else None
                return response.status, result, response.headers
        except HTTPError as exc:
            raw = exc.read()
            try:
                result = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                result = {"message": "GitHub returned a non-JSON error"}
            raise GitHubError(exc.code, "GitHub REST request was rejected", body=result) from None
        except (URLError, TimeoutError, OSError) as exc:
            if method.upper() in {"POST", "PATCH", "PUT", "DELETE"}:
                raise GitHubOutcomeUnknown("GitHub write response is unknown") from None
            raise GitHubError(503, "GitHub REST read failed") from None
        finally:
            if callable(lease):
                lease()

    def get(self, path):
        return self.request("GET", path)[1]

    def get_with_headers(self, path):
        _, data, headers = self.request("GET", path)
        return data, headers

    def write(self, method, path, body, headers=None):
        return self.request(method, path, body, headers=headers)

    def get_all(self, path):
        items = []
        next_url = self._path(path)
        visited = set()
        while next_url:
            if next_url in visited:
                raise GitHubError(502, "GitHub pagination loop detected")
            visited.add(next_url)
            _, data, headers = self.request("GET", next_url)
            if not isinstance(data, list):
                raise GitHubError(502, "GitHub paginated response is not an array")
            items.extend(data)
            links = headers.get("Link", "")
            next_url = None
            for part in links.split(","):
                if 'rel="next"' not in part:
                    continue
                start, end = part.find("<"), part.find(">")
                if start < 0 or end <= start:
                    raise GitHubError(502, "GitHub pagination link is malformed")
                next_url = self._path(part[start + 1:end])
                break
        return items


def repo_path(owner: str, name: str) -> str:
    return f"repos/{quote(owner, safe='')}/{quote(name, safe='')}"
