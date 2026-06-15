# FILE: backend/scanner/page_analyzer.py
# PURPOSE: Parse crawled HTML documents into normalized security-relevant page features
# SECURITY NOTE: Pure parser only; it never sends network requests or executes scripts

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from .schemas import FormInfo, FormInput, PageAnalysis, PageFeatures


class PageAnalyzer:
    """Converts existing crawler collection items into PageAnalysis objects."""

    API_PATH_RE = re.compile(r"['\"]((?:/api|/rest|/graphql|/v\d+/)[A-Za-z0-9_./?&=%:-]*)['\"]")

    def analyze(self, item: dict[str, Any]) -> PageAnalysis:
        url = str(item.get("url", ""))
        html = str(item.get("html", "") or "")
        headers = {str(k).lower(): str(v) for k, v in (item.get("headers") or {}).items()}
        soup = BeautifulSoup(html, "lxml")

        forms = self._extract_forms(soup, url, item.get("forms") or [])
        links = self._extract_links(soup, url, item.get("links") or [])
        scripts = self._extract_scripts(soup, url, item.get("scripts") or [])
        api_paths = self._extract_api_paths(soup, html, links, scripts)
        hidden = [inp for form in forms for inp in form.inputs if inp.input_type == "hidden"]
        csrf_tokens = [
            inp.name for inp in hidden
            if any(marker in inp.name.lower() for marker in ("csrf", "_token", "authenticity"))
        ]
        candidate_params = self._candidate_params(url, forms, links)
        visible_text = soup.get_text(" ", strip=True).lower()
        title = soup.title.string.strip() if soup.title and soup.title.string else ""

        return PageAnalysis(
            url=url,
            method=str(item.get("method", "GET")).upper(),
            status_code=int(item.get("status_code", 0) or 0),
            headers=headers,
            forms=forms,
            links=links,
            scripts=scripts,
            api_paths=api_paths,
            hidden_fields=hidden,
            csrf_tokens=csrf_tokens,
            candidate_params=candidate_params,
            features=self._detect_features(url, headers, visible_text, forms, links, api_paths),
            title=title,
        )

    def _extract_forms(self, soup: BeautifulSoup, base_url: str, existing: list[dict]) -> list[FormInfo]:
        forms: list[FormInfo] = []

        for raw in existing:
            inputs = [
                FormInput(
                    name=str(inp.get("name", "")),
                    input_type=str(inp.get("type", "text") or "text").lower(),
                    value=str(inp.get("value", "")),
                )
                for inp in raw.get("inputs", [])
                if inp.get("name")
            ]
            forms.append(FormInfo(
                action=urljoin(base_url, str(raw.get("action", base_url))),
                method=str(raw.get("method", "GET")).upper(),
                inputs=inputs,
            ))

        for form in soup.find_all("form"):
            inputs: list[FormInput] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id")
                if not name:
                    continue
                inputs.append(FormInput(
                    name=str(name),
                    input_type=str(inp.get("type", "text") or inp.name).lower(),
                    value=str(inp.get("value", "")),
                ))
            buttons = [btn.get_text(" ", strip=True) for btn in form.find_all("button")]
            forms.append(FormInfo(
                action=urljoin(base_url, str(form.get("action") or base_url)),
                method=str(form.get("method", "GET")).upper(),
                inputs=inputs,
                buttons=[b for b in buttons if b],
            ))

        return self._dedupe_forms(forms)

    def _extract_links(self, soup: BeautifulSoup, base_url: str, existing: list[str]) -> list[str]:
        links = [urljoin(base_url, href) for href in existing]
        links.extend(urljoin(base_url, a["href"]) for a in soup.find_all("a", href=True))
        return sorted(set(links))

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str, existing: list[str]) -> list[str]:
        scripts = [urljoin(base_url, src) for src in existing]
        scripts.extend(urljoin(base_url, s["src"]) for s in soup.find_all("script", src=True))
        return sorted(set(scripts))

    def _extract_api_paths(
        self,
        soup: BeautifulSoup,
        html: str,
        links: list[str],
        scripts: list[str],
    ) -> list[str]:
        paths = set(self.API_PATH_RE.findall(html))
        for tag in soup.find_all(attrs={"data-url": True}):
            paths.add(str(tag["data-url"]))
        for tag in soup.find_all(attrs={"data-api": True}):
            paths.add(str(tag["data-api"]))
        for href in links + scripts:
            path = urlparse(href).path
            if any(marker in path.lower() for marker in ("/api", "/rest", "/graphql", "swagger", "openapi")):
                paths.add(path)
        return sorted(paths)

    def _candidate_params(self, url: str, forms: list[FormInfo], links: list[str]) -> list[str]:
        params = set(parse_qs(urlparse(url).query).keys())
        for link in links:
            params.update(parse_qs(urlparse(link).query).keys())
        for form in forms:
            params.update(inp.name for inp in form.inputs if inp.input_type != "password")
        return sorted(params)

    def _detect_features(
        self,
        url: str,
        headers: dict[str, str],
        text: str,
        forms: list[FormInfo],
        links: list[str],
        api_paths: list[str],
    ) -> PageFeatures:
        path = urlparse(url).path.lower()
        field_names = " ".join(inp.name.lower() for form in forms for inp in form.inputs)
        link_text = " ".join(urlparse(link).path.lower() for link in links)
        content_type = headers.get("content-type", "").lower()
        combined = " ".join([path, field_names, link_text, text])

        return PageFeatures(
            is_login=bool(re.search(r"\b(login|signin|sign-in|password)\b", combined)),
            is_register=bool(re.search(r"\b(register|signup|sign-up|create account)\b", combined)),
            is_search=bool(re.search(r"\b(search|query|filter|q=)\b", combined)),
            is_basket=bool(re.search(r"\b(basket|cart|checkout|order)\b", combined)),
            is_profile=bool(re.search(r"\b(profile|account|settings|user)\b", combined)),
            is_admin=bool(re.search(r"\b(admin|administration|manage|dashboard|panel)\b", combined)),
            is_upload=bool(re.search(r"\b(upload|avatar|file|multipart)\b", combined)),
            is_comment=bool(re.search(r"\b(comment|review|feedback|message)\b", combined)),
            is_product=bool(re.search(r"\b(product|item|catalog|sku)\b", combined)),
            is_api=("json" in content_type or "/api" in path or "/rest" in path or bool(api_paths)),
            is_error=bool(re.search(r"\b(error|exception|stack trace|traceback|debug)\b", combined)),
        )

    def _dedupe_forms(self, forms: list[FormInfo]) -> list[FormInfo]:
        seen: set[tuple] = set()
        out: list[FormInfo] = []
        for form in forms:
            key = (form.action, form.method, tuple(sorted(inp.name for inp in form.inputs)))
            if key not in seen:
                seen.add(key)
                out.append(form)
        return out

