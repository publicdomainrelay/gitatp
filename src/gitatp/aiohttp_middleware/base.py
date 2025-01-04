import abc
import sys
import asyncio
import pathlib

import aiohttp.web

from ..util import git_subprocess

class AioHTTPGitHTTPBackend:
    @abc.abstractmethod
    async def on_startup(self, app):
        pass

    @abc.abstractmethod
    async def on_cleanup(self, app):
        pass

    @abc.abstractmethod
    async def pre_git_http_backend(self, request, namespace, repo_name, local_repo_path):
        pass

    @abc.abstractmethod
    async def git_receive_pack(self, request, namespace, repo_name, local_repo_path, push_options):
        pass

    def make_middleware(self):
        @aiohttp.web.middleware
        async def middleware(request, handler):
            nonlocal self
            if (
                request.path.endswith("/info/refs")
                or request.path.endswith("git-upload-pack")
                or request.path.endswith("git-receive-pack")
            ):
                return await self.git_http_backend(request)
            return await handler(request)
        return middleware

    async def git_http_backend(self, request):
        for find_git_url_path_end in [
            "/info/refs",
            "/git-upload-pack",
            "/git-receive-pack",
        ]:
            if request.path.endswith(find_git_url_path_end):
                git_path = request.path[
                    request.path.index(find_git_url_path_end):
                ]
                path_components = request.path[
                    :request.path.index(find_git_url_path_end)
                ].split("/")
                namespace = path_components[-2]
                repo_name = path_components[-1]
                break

        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        local_repo_path = pathlib.Path(self.git_project_root, namespace, f"{repo_name}.git")

        # Create repo if it should exist
        await self.pre_git_http_backend(request, namespace, repo_name, local_repo_path)

        # TODO Replace file with original after proc.wait()
        await (
            await asyncio.create_subprocess_exec(
                "git", "config", "receive.advertisePushOptions", "true",
                cwd=str(local_repo_path),
            )
        ).wait()

        path_info = f"{repo_name}.git{git_path}"
        print(f"path_info: {namespace}/{path_info}")
        env = {
            "GIT_PROJECT_ROOT": str(local_repo_path.parent),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": f"/{path_info}",
            "REMOTE_USER": request.remote or "",
            "REMOTE_ADDR": request.transport.get_extra_info("peername")[0],
            "REQUEST_METHOD": request.method,
            "QUERY_STRING": request.query_string,
            "CONTENT_TYPE": request.headers.get("Content-Type", ""),
        }

        # Copy relevant HTTP headers to environment variables
        for header in ("Content-Type", "User-Agent", "Accept-Encoding", "Pragma"):
            header_value = request.headers.get(header)
            if header_value:
                env["HTTP_" + header.upper().replace("-", "_")] = header_value

        # Prepare the subprocess to run git http-backend
        proc = await asyncio.create_subprocess_exec(
            "git", "http-backend",
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,  # Output stderr to the server's stderr
        )

        # Push options are parsed from git client upload pack
        push_options = {}

        # Create a StreamResponse to send data back to the client
        response = aiohttp.web.StreamResponse()

        # Run the read and write tasks concurrently
        await asyncio.gather(
            git_subprocess.write_to_git(proc.stdin, request, response, push_options),
            git_subprocess.read_from_git(proc.stdout, request, response),
            proc.wait(),
        )

        push_options = git_subprocess.PushOptions(**push_options)

        # Handle push events (git-receive-pack)
        if path_info.endswith("git-receive-pack"):
            await self.git_receive_pack(
                request,
                namespace,
                repo_name,
                local_repo_path,
                push_options,
            )

        return response
