from app.security import classify, valid_ip
import pytest

def test_detects_sql_injection():
    assert classify("/items", "q=UNION SELECT password FROM users")[0] == "sql_injection"

def test_detects_path_traversal():
    assert classify("/../../etc/passwd", "")[0] == "path_traversal"

def test_normalizes_ip():
    assert valid_ip("203.0.113.4") == "203.0.113.4"

def test_rejects_invalid_ip():
    with pytest.raises(ValueError): valid_ip("not-an-ip")
