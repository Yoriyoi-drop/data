from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.middleware.cors import CORSConfig
from litestar.responses import PlainText
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    user = get_user(payload["username"])  # type: ignore[index]
    if not user:
        return {"detail": "Invalid credentials"}

    token = sign_jwt({"sub": payload["username"]})  # type: ignore[index]
    return {"access_token": token, "token_type": "bearer"}


@post(path="/api/analyze")
async def analyze(data: dict) -> dict:
    try:
        payload = AnalyzePayloadSchema().load(data)
    except ValidationError as e:
        return {"detail": e.messages}

    return {
        "analysis": {
            "threat": False,
            "context": payload.get("context"),
        }
    }


@get(path="/metrics")
async def metrics() -> PlainText:
    return PlainText(generate_latest().decode("utf-8"))


cors = CORSConfig(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app = Litestar(
    route_handlers=[health, login, analyze, metrics],
    cors_config=cors,
    after_request=[security_headers_hook],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("litestar_app.app:app", host="0.0.0.0", port=8002)
from litestar import Litestar, get, post
from litestar.response import Response
from litestar.middleware.cors import CORSConfig
from marshmallow import ValidationError
from prometheus_client import generate_latest

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user
from .middleware.security import security_headers_hook


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> Response:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return Response({
from litestar import Litestar, get, post
from litestar.response import Response
from litestar.middleware.cors import CORSConfig
from litestar.types import Scope
from marshmallow import ValidationError
from prometheus_client import generate_latest
import os

from .schemas.auth import LoginPayloadSchema
from .schemas.analyze import AnalyzePayloadSchema
from .security.jwt import sign_jwt
from .db.pg import get_user


@get("/health")
async def health() -> dict:
    return {"status": "healthy", "version": "2.0.0"}


@post(path="/auth/login")
async def login(data: dict) -> dict:
    try:
        payload = LoginPayloadSchema().load(data)
    except ValidationError as e:
        return Response({
