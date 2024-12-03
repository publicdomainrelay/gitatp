import asyncio

import textwrap
import pathlib
import subprocess

from .git_http_backend import *

import magic
import snoop

def file_contents_bytes_to_markdown(file_path: str, content: bytes) -> str:
    mime = magic.Magic(mime=True)
    mime_type = mime.from_buffer(content)
    string_content = content.decode('utf-8')

    if pathlib.Path(file_path).suffix == ".md" or mime_type == "text/markdown":
        return string_content
    elif mime_type == "text/plain":
        return f"```\n{string_content}\n```"
    elif mime_type.startswith("text"):
        code_block_type = mime_type.split('/')[1]
        if code_block_type.startswith("x-script."):
            code_block_type = code_block_type[len("x-script."):]
        return f"```{code_block_type}\n{string_content}\n```"
    else:
        return f"```\n{string_content}\n```"

import markdown2
from pygments.formatters import HtmlFormatter

from fastapi import FastAPI
from aiohttp import web
from aiohttp_asgi import ASGIResource
from datetime import date
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastui import FastUI, AnyComponent, prebuilt_html, components as c
from fastui.components.display import DisplayMode, DisplayLookup
from fastui.events import GoToEvent, BackEvent
from pydantic import BaseModel, Field

# Step 1: Define your FastAPI app
fastapi_app = FastAPI()

@fastapi_app.get(
    "/{namespace}/{repo_name}/blob/{ref}/{path:path}",
    response_class=HTMLResponse,
    response_model_exclude_none=True,
)
def render_content(namespace: str, repo_name: str, ref: str, path: str) -> HTMLResponse:
    if not repo_name.endswith(".git"):
        repo_name = f"{repo_name}.git"
    repo_path = pathlib.Path(GIT_PROJECT_ROOT, namespace, repo_name)

    cmd = [
        "git",
        "show",
        f"{ref}:{path}"
    ]
    try:
        file_contents_bytes = subprocess.check_output(
            cmd,
            cwd=str(repo_path.resolve()),
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail="File not found") from e

    markdown_content = file_contents_bytes_to_markdown(
        path,
        file_contents_bytes,
    )
    rendered_html = markdown2.markdown(
        markdown_content,
        extras=[
            "fenced-code-blocks",
            "code-friendly",
            "highlightjs-lang",
        ],
    )

    return textwrap.dedent(
        f"""
        <html>
            <title>{path}</title>
            <body>
                {rendered_html}
            </body>
        </html>
        """.strip()
    )

# Step 2: Define an aiohttp app and adapt the FastAPI app
async def init_aiohttp_app():
    aiohttp_app = web.Application()

    # Create ASGIResource which handle rendering
    asgi_resource = ASGIResource(fastapi_app)

    # Register routes
    aiohttp_app.router.add_route("*", "/{namespace}/{repo}.git/{path:.*}", handle_git_backend_request)

    # Register resource
    aiohttp_app.router.register_resource(asgi_resource)

    # Mount startup and shutdown events from aiohttp to ASGI app
    asgi_resource.lifespan_mount(aiohttp_app)

    return aiohttp_app

def main() -> None:
    loop = asyncio.get_event_loop()
    aiohttp_app = loop.run_until_complete(init_aiohttp_app())

    # Start the server
    web.run_app(aiohttp_app, host="0.0.0.0", port=8080)
