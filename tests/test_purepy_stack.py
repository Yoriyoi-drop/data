from marshmallow import Schema, fields
from passlib.hash import pbkdf2_sha256
import pg8000


def test_marshmallow_validate_and_dump():
    class M(Schema):
        a = fields.Int(required=True)
        b = fields.Str(required=True)

    data = {"a": 1, "b": "x"}
    loaded = M().load(data)
    dumped = M().dump(loaded)
    assert dumped == data


def test_passlib_pbkdf2():
    h = pbkdf2_sha256.hash("secret123")
    assert pbkdf2_sha256.verify("secret123", h)


def test_pg8000_import():
    assert hasattr(pg8000, "connect")
