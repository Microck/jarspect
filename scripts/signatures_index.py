#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def main() -> int:
    try:
        endpoint = _required_env("AZURE_SEARCH_ENDPOINT")
        api_key = _required_env("AZURE_SEARCH_API_KEY")
        index_name = _required_env("AZURE_SEARCH_INDEX")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        from azure.core.credentials import AzureKeyCredential
        from azure.search.documents import SearchClient
    except ImportError:
        print("Install azure-search-documents to run indexing script.", file=sys.stderr)
        return 1

    root = Path(__file__).resolve().parents[1]
    corpus_path = root / "data" / "signatures" / "signatures.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))

    documents = [
        {
            "id": item["id"],
            "kind": item["kind"],
            "value": item["value"],
            "severity": item["severity"],
            "description": item["description"],
        }
        for item in corpus
    ]

    client = SearchClient(
        endpoint=endpoint,
        index_name=index_name,
        credential=AzureKeyCredential(api_key),
    )
    result = client.merge_or_upload_documents(documents)
    print(f"Indexed {len(result)} signatures into '{index_name}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
