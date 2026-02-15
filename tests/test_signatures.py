from __future__ import annotations

from mod_sentinel.signatures.local_json import LocalJsonSignatureStore


def test_signature_store_finds_known_token() -> None:
    store = LocalJsonSignatureStore()
    text = 'Runtime.getRuntime().exec("calc.exe");'

    matches = store.search(text)
    assert any(match.id == "SIG-TOKEN-RUNTIME-EXEC" for match in matches)


def test_signature_store_returns_empty_on_clean_input() -> None:
    store = LocalJsonSignatureStore()
    text = "public class Demo { public void hello() {} }"

    assert store.search(text) == []
