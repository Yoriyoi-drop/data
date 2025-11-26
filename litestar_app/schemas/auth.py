from marshmallow import Schema, fields

class LoginPayloadSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
