from marshmallow import Schema, fields


class LoginPayloadSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class AnalyzePayloadSchema(Schema):
    input = fields.Str(required=True)
    context = fields.Str(allow_none=True)
