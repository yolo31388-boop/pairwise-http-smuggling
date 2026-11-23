import pytest
import security.http_smuggling as mod

CASES = [
    ("reject_ambiguous", (1, 2)),
    ("unified_parser", (1, 2)),
    ("header_length", (1, 2)),
    ("te_disable", (1, 2)),
    ("cl_check", (1, 2)),
    ("smuggling_detect", (1, 2)),
    ("proxy_consistency", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("error_map", (1, 2)),
    ("rate_limit", (1, 2)),
    ("logging", (1, 2)),
    ("fallback", (1, 2)),
    ("body_limit", (1, 2)),
    ("test_vectors", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
