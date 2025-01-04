import sys
import pathlib
import traceback

from pydantic import BaseModel, Field, AliasChoices

class PushOptions(BaseModel):
    branch: str = None
    pr_branch: str = Field(
        validation_alias=AliasChoices('pr.branch'),
        default=None,
    )
    pr_ns: str = Field(
        validation_alias=AliasChoices('pr.ns'),
        default=None,
    )
    pr_repo: str = Field(
        validation_alias=AliasChoices('pr.repo'),
        default=None,
    )

def parse_push_options(chunk: bytes):
    push_options = {}
    if b"agent=" in chunk and b"0000PACK" in chunk:
        chunk_header = chunk[
            :chunk.index(b"0000PACK")
        ]
        push_data = chunk_header[
            :chunk_header.index(b"\x00")
        ].decode(
            "latin1", errors="ignore",
        )
        push_options["branch"] = push_data.split()[-1]
        chunk_header = chunk_header[
            chunk_header.index(b"\x00"):
        ]
        if b"0000" in chunk_header:
            chunk_header = chunk_header[
                chunk_header.index(b"0000") + 4:
            ]
            chunk_header = chunk_header.decode(
                "latin1", errors="ignore",
            )
            while chunk_header:
                chunk_header_size = int(chunk_header[:4], 16)
                chunk_header_value = chunk_header[4:chunk_header_size]
                chunk_header = chunk_header[chunk_header_size:]
                if "=" in chunk_header_value:
                    key, value = chunk_header_value.split("=")
                    push_options[key] = value
    return push_options

async def write_to_git(stdin, request, response, push_options):
    try:
        async for chunk in request.content.iter_chunked(4096):
            push_options.update(parse_push_options(chunk))
            stdin.write(chunk)
        await stdin.drain()
    except Exception as e:
        print(f"Error writing to git http-backend: {traceback.format_exc()}", file=sys.stderr)
    finally:
        if not stdin.is_closing():
            stdin.close()

# Read the response from git http-backend and send it back to the client
async def read_from_git(stdout, request, response):
    headers = {}
    headers_received = False
    buffer = b""

    while True:
        chunk = await stdout.read(4096)
        if not chunk:
            break
        buffer += chunk
        if not headers_received:
            header_end = buffer.find(b'\r\n\r\n')
            if header_end != -1:
                header_data = buffer[:header_end].decode('utf-8', errors='replace')
                body = buffer[header_end+4:]
                # Parse headers
                for line in header_data.split('\r\n'):
                    if line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                # Send headers to the client
                for key, value in headers.items():
                    response.headers[key] = value
                await response.prepare(request)
                await response.write(body)
                headers_received = True
                buffer = b""
        else:
            # Send body to the client
            await response.write(chunk)
    if not headers_received:
        # If no headers were sent, send what we have
        await response.prepare(request)
        await response.write(buffer)
    await response.write_eof()

# Utility to list all internal files in a Git repository
def list_git_internal_files(repo_path):
    files = []
    git_dir = pathlib.Path(repo_path)
    for file in git_dir.rglob("*"):
        if file.is_file():
            yield file
