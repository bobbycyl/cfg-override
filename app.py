import tomllib
from io import BytesIO
from urllib.parse import quote, urlparse

import orjson
import safehttpx as sh
import tomli_w
import uvicorn
from dictmerge.dictmerge import merge_one
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

ALLOWED_SCHEME = frozenset(["http", "https"])
TIMEOUT = 10.0
# noinspection SpellCheckingInspection
RULE_ENABLE_AUTO_REDIRECT = {
    "inbounds!": [
        {
            "type": "tun",
            "address": [
                "172.18.0.1/30",
                "fdfe:dcba:9876::1/126",
            ],
            "auto_route": True,
            "auto_redirect": True,
            "strict_route": True,
            "route_address": [
                "0.0.0.0/1",
                "128.0.0.0/1",
                "::/1",
                "8000::/1",
            ],
            "route_exclude_address_set": [
                "geoip-cn",
            ],
            "route_exclude_address": [
                "172.18.0.0/16",
                "192.168.0.0/16",
            ],
        },
    ],
}
RULES: dict[int, dict] = {
    0: RULE_ENABLE_AUTO_REDIRECT,
}


def validate_url(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEME:
        raise HTTPException(400, f"scheme not allowed: {p.scheme}")
    if not p.hostname:
        raise HTTPException(400, "missing hostname")


async def fetch_base(url: str) -> str:
    resp = await sh.get(url, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text


app = FastAPI(
    title="cfg-override",
    description="override config file",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# noinspection bad-argument-type
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/override")
async def override(request: Request) -> StreamingResponse:
    try:
        base_url = request.query_params["base"]
    except KeyError:
        raise HTTPException(status_code=400, detail="missing base url")
    validate_url(base_url)
    try:
        rule_id = int(request.query_params["rule"])
    except KeyError:
        raise HTTPException(status_code=400, detail="missing rule id")
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid rule id")
    try:
        ext = request.query_params["ext"].lower()
    except KeyError:
        raise HTTPException(status_code=400, detail="missing extension")
    if ext not in ("json", "toml"):
        raise HTTPException(status_code=400, detail="invalid extension")
    try:
        filename = request.query_params["filename"]
    except Exception:
        raise HTTPException(status_code=400, detail="missing filename")

    try:
        base_str: str = await fetch_base(base_url)
    except Exception:
        raise HTTPException(status_code=502, detail="failed to fetch base config")
    try:
        if ext == "json":
            base = orjson.loads(base_str)
        elif ext == "toml":
            base = tomllib.loads(base_str)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid base config")

    if rule_id not in RULES:
        raise HTTPException(status_code=400, detail="rule not found")
    merged = merge_one(base, RULES[rule_id])

    buf = BytesIO()

    if ext == "json":
        buf.write(orjson.dumps(merged))
    elif ext == "toml":
        tomli_w.dump(merged, buf)

    buf.seek(0)
    safe_filename = quote(filename, safe="")
    return StreamingResponse(buf, media_type=f"application/{ext}", headers={"Content-Disposition": f"attachment; filename*={safe_filename}"})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
