from __future__ import annotations

from mod_sentinel.signatures.store import SignatureMatch, SignatureStore


class AzureSearchSignatureStore(SignatureStore):
    def __init__(
        self,
        endpoint: str | None,
        api_key: str | None,
        index_name: str | None,
    ) -> None:
        if not endpoint:
            raise ValueError(
                "AZURE_SEARCH_ENDPOINT is required for azure search signature store"
            )
        if not api_key:
            raise ValueError(
                "AZURE_SEARCH_API_KEY is required for azure search signature store"
            )
        if not index_name:
            raise ValueError(
                "AZURE_SEARCH_INDEX is required for azure search signature store"
            )

        try:
            from azure.core.credentials import AzureKeyCredential
            from azure.search.documents import SearchClient
        except ImportError as exc:
            raise RuntimeError(
                "azure-search-documents dependency is required for AzureSearchSignatureStore"
            ) from exc

        self._client = SearchClient(
            endpoint=endpoint,
            index_name=index_name,
            credential=AzureKeyCredential(api_key),
        )

    def search(self, text: str) -> list[SignatureMatch]:
        results = self._client.search(search_text=text, top=10)
        matches: list[SignatureMatch] = []
        for doc in results:
            signature_id = str(doc.get("id", ""))
            if not signature_id:
                continue
            value = str(doc.get("value", ""))
            offset = text.find(value) if value else -1
            end_offset = offset + len(value) if offset >= 0 else -1
            evidence = (
                value
                if offset < 0
                else text[max(offset - 80, 0) : min(end_offset + 80, len(text))]
            )
            matches.append(
                SignatureMatch(
                    id=signature_id,
                    severity=str(doc.get("severity", "med")),
                    description=str(doc.get("description", "")),
                    evidence=evidence,
                    offset=max(offset, 0),
                    end_offset=max(end_offset, 0),
                )
            )
        return matches
