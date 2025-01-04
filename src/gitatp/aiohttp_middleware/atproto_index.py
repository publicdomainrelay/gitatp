import os
import json
import atexit
import asyncio
import pprint
import warnings
import pathlib
from pathlib import Path
from io import BytesIO
from typing import Optional
import zipfile
import hashlib
import subprocess

import aiohttp.web
from pydantic import BaseModel, Field
from atproto import AsyncClient, models
import atprotobin.zip_image
import snoop

from ..util.zip_image import *
from ..util import git_subprocess
from .base import AioHTTPGitHTTPBackend

# Helper scripts for APIs not available to Python client, etc.
# TODO importlib.resources once packaged
ATPROTO_UPDATE_PROFILE_JS_PATH = Path(__file__).parent.resolve().joinpath("update_profile.js")

# TODO Make hash_alg and allowd_hash_algs configurable
hash_alg = 'sha384'
allowed_hash_algs = ['sha256', hash_alg, 'sha512']

# TODO DEBUG REMOVE
# os.environ["HOME"] = str(Path(__file__).parent.resolve())

class CacheATProtoBlob(BaseModel):
    hash_alg: str
    hash_value: str
    cid: str
    did: str

class CacheATProtoIndex(BaseModel):
    text: str
    owner_profile: Optional[models.app.bsky.actor.defs.ProfileViewBasic] = None
    post: Optional[models.base.RecordModelBase] = None
    root: Optional[models.base.RecordModelBase] = None
    parent: Optional[models.base.RecordModelBase] = None
    blob: Optional[CacheATProtoBlob] = None
    entries: dict[str, 'CacheATProtoIndex'] = Field(
        default_factory=lambda: {},
    )

class CacheATProtoNamespace(BaseModel):
    owner_profile: Optional[models.app.bsky.actor.defs.ProfileViewBasic] = None
    index: Optional[CacheATProtoIndex] = None

class CacheATProtoNamespaces(BaseModel):
    owner_profile: Optional[models.app.bsky.actor.defs.ProfileViewBasic] = None
    namespaces: dict[str, CacheATProtoNamespace] = Field(
        default_factory=lambda: {},
    )

async def update_profile(client, config, pinned_post):
    # TODO Use Python client APIs once available
    env = {
        **os.environ,
        **{
            "ATPROTO_BASE_URL": config.atproto_base_url,
            "ATPROTO_HANDLE": config.atproto_handle,
            "ATPROTO_PASSWORD": config.atproto_password,
            "ATPROTO_PINNED_POST_URI": pinned_post.uri,
            "ATPROTO_PINNED_POST_CID": pinned_post.cid,
        },
    }
    update_profile_deno_cache_path = Path(
        "~", ".cache", "update_profile_deno_cache_path",
    ).expanduser()
    update_profile_deno_cache_path.mkdir(parents=True, exist_ok=True)

    update_profile_deno_cache_path.joinpath(
        ATPROTO_UPDATE_PROFILE_JS_PATH.name,
    ).write_bytes(
        ATPROTO_UPDATE_PROFILE_JS_PATH.read_bytes(),
    )

    if not update_profile_deno_cache_path.joinpath("deno.lock").exists():
        cmd = [
            "deno",
            "add",
            "npm:@atproto/api",
        ]
        proc_result = subprocess.run(
            cmd,
            cwd=str(update_profile_deno_cache_path.resolve()),
        )
        proc_result.check_returncode()

    cmd = [
        "deno",
        "--allow-env",
        "--allow-net",
        str(ATPROTO_UPDATE_PROFILE_JS_PATH.name),
    ]
    proc_result = subprocess.run(
        cmd,
        cwd=str(update_profile_deno_cache_path.resolve()),
        env=env,
    )
    proc_result.check_returncode()

# TODO Add ctx with policy object and grab owners from atprotobin style manifest
async def atproto_index_read_recurse(client, index, index_entry):
    # TODO Support for pull requests. Maintiners MAY push to group repo.
    # Maintainers and others SHOULD pull request group repo.
    # FIXME FIXME FIXME
    # TODO If there is a later reply in the thread with the same text and it's a
    # file __getattr__() on the CacheATProtoIndex object should resolve down the
    # chain using traverse_config_get(target, *args) unified config stuff.
    # FIXME FIXME FIXME
    owner_dids = [index.owner_profile.did]
    if index_entry.replies is not None:
        for reply_entry in index_entry.replies:
            if reply_entry.post.author.did not in owner_dids:
                return
            # pprint.pprint(json.loads(index_entry.model_dump_json()))
            sub_index_kwargs = {}
            if (
                reply_entry.post.record.embed
                and reply_entry.post.record.embed.images
            ):
                sub_index_kwargs["blob"] = {
                    "hash_alg": reply_entry.post.record.embed.images[0].alt.split(":", maxsplit=1)[0],
                    "hash_value": reply_entry.post.record.embed.images[0].alt.split(":", maxsplit=1)[1],
                    "cid": reply_entry.post.record.embed.images[0].image.ref.link,
                    "did": reply_entry.post.author.did,
                }
            sub_index_kwargs["root"] = {
                "uri": reply_entry.post.record.reply.root.uri,
                "cid": reply_entry.post.record.reply.root.cid,
            }
            sub_index_kwargs["parent"] = {
                "uri": reply_entry.post.record.reply.parent.uri,
                "cid": reply_entry.post.record.reply.parent.cid,
            }
            sub_index = index.__class__(
                text=reply_entry.post.record.text,
                owner_profile=reply_entry.post.author,
                post={
                    "uri": reply_entry.post.uri,
                    "cid": reply_entry.post.cid,
                },
                **sub_index_kwargs,
            )
            await atproto_index_read_recurse(client, sub_index, reply_entry)
            if index_entry.post.record.text in index.entries:
                index.entries[reply_entry.post.record.text].entries.update(
                    sub_index.entries,
                )
            else:
                index.entries[reply_entry.post.record.text] = sub_index

# index_entry = client.get_posts([index.post.uri])
async def atproto_index_read(client, index, depth: int = None):
    for index_type, index_entry in (
        await client.get_post_thread(
            index.post.uri,
            depth=depth,
        )
    ):
        # snoop.pp(index_type, index_entry)
        if index_type == 'thread':
            await atproto_index_read_recurse(client, index, index_entry)
        elif index_type == 'threadgate':
            pass
        else:
            warnings.warn(f"Unkown get_post_thread().index_type: {index_type!r}: {pprint.pformat(index_entry)}")

class FileContentsToEncode(BaseModel):
    name: str
    data: bytes

class FilePathToEncode(BaseModel):
    repo_path: pathlib.Path
    local_path: pathlib.Path

async def atproto_index_create(client, index, index_entry_key, data_as_image: bytes = None, data_as_image_hash: str = None, encode_contents: FileContentsToEncode = None, encode_path: FilePathToEncode = None):
    if int(os.environ.get("GITATP_NO_SYNC", "0")):
        return

    global hash_alg

    hash_instance = hashlib.new(hash_alg)
    if encode_contents is not None:
        hash_instance.update(encode_contents.data)
        _mimetype, data_as_image = atprotobin.zip_image.encode(
            encode_contents.data, encode_contents.name,
        )
    if encode_path is not None:
        hash_instance.update(encode_path.local_path.read_bytes())
        data_as_image = create_png_with_zip(
            create_zip_of_files(
                encode_path.repo_path, [encode_path.local_path],
            )
        )
    if data_as_image is not None:
        data_as_image_hash = f"{hash_alg}:{hash_instance.hexdigest()}"

    parent = models.create_strong_ref(index.post)
    root = models.create_strong_ref(index.root)
    if index_entry_key in index.entries:
        if data_as_image_hash is None:
            # Index without data already exists, NOP
            return False, index.entries[index_entry_key]
        hash_alg = data_as_image_hash.split(":", maxsplit=1)[0]
        hash_value = data_as_image_hash.split(":", maxsplit=1)[1]
        if (
            hash_alg == index.entries[index_entry_key].blob.hash_alg
            and hash_value == index.entries[index_entry_key].blob.hash_value
        ):
            # Index entry with same data already exists, NOP
            return False, index.entries[index_entry_key]
        # Fall through and create new version with ref to old as parent
        # TODO Get thread if the would be parent post has any unloaded replies
        parent = models.create_strong_ref(index.entries[index_entry_key].post)
    method = client.send_post
    kwargs = {}
    if data_as_image is not None:
        method = client.send_image
        kwargs["image"] = data_as_image
        if data_as_image_hash is not None:
            kwargs["image_alt"] = data_as_image_hash
    post = await method(
        text=index_entry_key,
        reply_to=models.AppBskyFeedPost.ReplyRef(parent=parent, root=root),
        **kwargs,
    )
    index_kwargs = {}
    if data_as_image is not None:
        index_kwargs["blob"] = {
            "hash_alg": data_as_image_hash.split(":", maxsplit=1)[0],
            "hash_value": data_as_image_hash.split(":", maxsplit=1)[1],
            "cid": post.cid,
            "did": post.uri.split("/")[2],
        }
    index.entries[index_entry_key] = index.__class__(
        text=index_entry_key,
        owner_profile=index.owner_profile,
        post={
            "uri": post.uri,
            "cid": post.cid,
        },
        root={
            "uri": root.uri,
            "cid": root.cid,
        },
        parent={
            "uri": parent.uri,
            "cid": parent.cid,
        },
        **index_kwargs,
    )
    return True, index.entries[index_entry_key]

# TODO Do this directly on the git repos instead of having a repos dir

async def download_from_atproto_to_local_repos_directory_git(client, git_project_root, namespace, repo_name, index):
    # TODO Context for projects root
    # Ensure the project root exists
    os.makedirs(git_project_root , exist_ok=True)
    if not repo_name.endswith(".git"):
        repo_name = f"{repo_name}.git"
    repo_path = Path(git_project_root, namespace, repo_name)
    for index_entry_key, index_entry in index.entries.items():
        if not index_entry.blob or not index_entry.blob.cid:
            warnings.warn(f"{index.text!r} is not a file, offending index node: {pprint.pprint(json.loads(index.model_dump_json()))}")
        # TODO Probably should look at path traversal
        internal_file = repo_path.joinpath(index_entry.text)
        repo_file_path = str(internal_file.relative_to(repo_path))
        re_download = False
        if not internal_file.exists():
            re_download = True
        else:
            if not index_entry.blob:
                snoop.pp(index_entry)
            if index_entry.blob.hash_alg not in allowed_hash_algs:
                raise ValueError(f"{index_entry.blob.hash_alg!r} is not in allowed_hash_algs, offending index node: {pprint.pprint(json.loads(index_entry.model_dump_json()))}")
            hash_instance = hashlib.new(index_entry.blob.hash_alg)
            hash_instance.update(internal_file.read_bytes())
            hash_digest_local = hash_instance.hexdigest()
            if hash_digest_local != index_entry.blob.hash_value:
                warnings.warn(f"{index_entry.text} {index_entry.blob.hash_alg} mismatch local: {hash_digest_local} != remote: {index_entry.blob.hash_value}")
                re_download = True
        if not re_download:
            print(f"Internal file for {repo_name} is up to date: {repo_file_path}")
        else:
            print(f"Downloading internal file to {repo_name}: {repo_file_path}")
            # TODO Timestamps or something
            blob = await client.com.atproto.sync.get_blob(
                models.com.atproto.sync.get_blob.Params(
                    cid=index_entry.blob.cid,
                    did=index_entry.blob.did,
                ),
            )
            zip_data = extract_zip_from_png(blob)
            extract_zip_of_files(repo_path, zip_data, [index_entry.text])
            print(f"Successful download of internal file to {repo_name}: {repo_file_path}")


class AioHTTPGitHTTPBackendATProtoConfig(BaseModel):
    atproto_base_url: str
    atproto_handle: str
    atproto_password: str
    repos_directory: pathlib.Path

class AioHTTPGitHTTPBackendATProto(AioHTTPGitHTTPBackend):
    def __init__(self, config):
        self.config = config
        self.setup_cache()

    def setup_cache(self):
        atproto_cache = CacheATProtoNamespaces()
        self.atproto_cache = atproto_cache
        # TODO Path from config
        atproto_cache_path = Path("~", ".cache", "atproto_vcs_git_cache.json").expanduser()
        atproto_cache_path.parent.mkdir(parents=True, exist_ok=True)
        atexit.register(
            lambda: atproto_cache_path.write_text(
                atproto_cache.model_dump_json(),
            )
        )
        if False and atproto_cache_path.exists():
            atproto_cache = CacheATProtoIndex.model_validate_json(atproto_cache_path.read_text())
        atproto_cache.namespaces.setdefault(
            self.config.atproto_handle,
            CacheATProtoNamespace(
                index=CacheATProtoIndex(text="index"),
            )
        )
        atproto_namespace = atproto_cache.namespaces[self.config.atproto_handle]
        self.atproto_namespace = atproto_namespace
        atproto_index = atproto_namespace.index
        self.atproto_index = atproto_index

    async def on_startup(self, app):
        self.app_key = aiohttp.web.AppKey(
            "git_http_backend_atproto_client",
            AsyncClient,
        )

        client = AsyncClient(
            base_url=self.config.atproto_base_url,
        )
        app[self.app_key] = client

        await client.login(
            self.config.atproto_handle,
            self.config.atproto_password,
        )

        if self.atproto_index.owner_profile is None:
            self.atproto_index.owner_profile = await client.get_profile(
                self.config.atproto_handle,
            )
        self.atproto_index.root = self.atproto_index.owner_profile.pinned_post

        atproto_index = self.atproto_index

        # Configuration
        self.git_project_root = self.config.repos_directory
        # Ensure the project root exists
        os.makedirs(self.git_project_root, exist_ok=True)

        if atproto_index.root is None:
            post = await client.send_post(text="index")
            await update_profile(client, self.config, pinned_post=post)
            atproto_index.root = post

        # For top level index all props are the same
        atproto_index.post = atproto_index.root
        atproto_index.parent = atproto_index.root

        # NOTE If you delete the index without unpinning first everything breaks
        await atproto_index_read(client, atproto_index, depth=2)
        await atproto_index_create(client, atproto_index, "vcs")
        await atproto_index_create(client, atproto_index.entries["vcs"], "git")

    async def on_cleanup(self, app):
        del app[self.app_key]

    async def pre_git_http_backend(self, request, namespace, repo_name, local_repo_path):
        client = request.app[self.app_key]

        atproto_cache = self.atproto_cache
        atproto_cache.namespaces.setdefault(
            namespace,
            CacheATProtoNamespace(
                index=CacheATProtoIndex(text="index"),
            )
        )
        atproto_namespace = atproto_cache.namespaces[namespace]
        atproto_index = atproto_namespace.index
        if not int(os.environ.get("GITATP_NO_SYNC", "0")):
            if atproto_index.owner_profile is None:
                atproto_index.owner_profile = await client.get_profile(namespace)
            atproto_index.root = atproto_index.owner_profile.pinned_post
        atproto_index.post = atproto_index.root
        atproto_index.parent = atproto_index.root

        # Ensure there is a bare Git repository for testing
        if not local_repo_path.is_dir():
            local_repo_path.parent.mkdir(parents=True, exist_ok=True)
            os.system(f"git init --bare {local_repo_path}")
            os.system(f"rm -rf {local_repo_path}/hooks/")

        # Sync from ATProto
        if not int(os.environ.get("GITATP_NO_SYNC", "0")):
            await atproto_index_read(client, atproto_index, depth=2)
            if (
                "vcs" in atproto_index.entries
                and "git" in atproto_index.entries["vcs"].entries
            ):
                await atproto_index_read(client, atproto_index.entries["vcs"].entries["git"])
                if repo_name in atproto_index.entries["vcs"].entries["git"].entries:
                    atproto_repo = atproto_index.entries["vcs"].entries["git"].entries[repo_name]
                    if (
                        ".git" in atproto_repo.entries
                        and "metadata" in atproto_repo.entries
                    ):
                        await download_from_atproto_to_local_repos_directory_git(
                            client,
                            self.git_project_root,
                            namespace,
                            repo_name,
                            atproto_repo.entries[".git"],
                        )

    async def git_receive_pack_upload_internal_file(self, client, _namespace, repo_name, atproto_repo, local_repo_path, internal_file):
        repo_file_path = str(internal_file.relative_to(local_repo_path))
        created, cached = await atproto_index_create(
            client,
            atproto_repo.entries[".git"],
            repo_file_path,
            encode_path=FilePathToEncode(
                repo_path=local_repo_path,
                local_path=internal_file,
            ),
        )
        if created:
            print(f"Updated internal file in {repo_name}: {repo_file_path}")

    async def git_receive_pack(self, request, namespace, repo_name, local_repo_path, push_options):
        if int(os.environ.get("GITATP_NO_SYNC", "0")):
            return

        # TODO Does it matter if we do this one way vs. the other?
        client = request.app[self.app_key]
        atproto_index = self.atproto_index

        # TODO Better way for transparent .git on local repo directories
        # TODO Use atprotobin.zip_image on all non-binary files
        await atproto_index_create(client, atproto_index.entries["vcs"].entries["git"], repo_name)
        atproto_repo = atproto_index.entries["vcs"].entries["git"].entries[repo_name]
        await asyncio.gather(
            atproto_index_create(client, atproto_repo, ".git"),
            atproto_index_create(client, atproto_repo, "metadata"),
            atproto_index_create(client, atproto_repo, "pull_requests"),
        )
        await asyncio.gather(
            *[
                self.git_receive_pack_upload_internal_file(
                    client,
                    namespace,
                    repo_name,
                    atproto_repo,
                    local_repo_path,
                    internal_file,
                )
                for internal_file in git_subprocess.list_git_internal_files(local_repo_path)
            ]
        )

        # Update each branches manifest if needed
        cmd = [
            "git",
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/",
        ]
        branches_bytes = subprocess.check_output(
            cmd,
            cwd=str(local_repo_path.resolve()),
        )
        for branch_name in branches_bytes.decode().split("\n"):
            branch_name = branch_name.replace("'", "").strip()
            if not branch_name:
                continue
            # TODO Validate this
            if branch_name.startswith("refs/heads/"):
                branch_name = branch_name[len("refs/heads/"):]
            cmd = [
                "git",
                "show",
                f"{branch_name}:.tools/open-architecture/governance/branches/{branch_name}/policies/upstream.yml",
            ]
            try:
                manifest_contents_bytes = subprocess.check_output(
                    cmd,
                    stderr=subprocess.PIPE,
                    cwd=str(local_repo_path.resolve()),
                )

                created, cached = await atproto_index_create(
                    client,
                    atproto_index.entries["vcs"].entries["git"].entries[repo_name].entries["metadata"],
                    f".tools/open-architecture/governance/branches/{branch_name}/policies/upstream.yml",
                    encode_contents=FileContentsToEncode(
                        name=f".tools/open-architecture/governance/branches/{branch_name}/policies/upstream.yml",
                        data=manifest_contents_bytes,
                    ),
                )
                if created:
                    print(f"Updated metadata file in {repo_name}: .tools/open-architecture/governance/branches/{branch_name}/policies/upstream.yml")
            except subprocess.CalledProcessError as e:
                if b"does not exist in" not in e.stderr:
                    snoop.pp(e, e.stderr)
                    raise

        # Pull requests
        our_atproto_index = atproto_index
        if (
            push_options.pr_ns
            and push_options.pr_repo
            and push_options.pr_branch
        ):
            # Post reply of base branch to target branch to pull_requests
            namespace = push_options.pr_ns
            atproto_cache = self.atproto_cache
            atproto_cache.namespaces.setdefault(
                namespace,
                CacheATProtoNamespace(
                    index=CacheATProtoIndex(text="index"),
                )
            )
            atproto_namespace = atproto_cache.namespaces[namespace]
            atproto_index = atproto_namespace.index
            if atproto_index.owner_profile is None:
                atproto_index.owner_profile = await client.get_profile(namespace)
            atproto_index.root = atproto_index.owner_profile.pinned_post
            atproto_index.post = atproto_index.root
            atproto_index.parent = atproto_index.root

            await atproto_index_read(client, atproto_index, depth=2)

            if (
                "vcs" in atproto_index.entries
                and "git" in atproto_index.entries["vcs"].entries
            ):
                await atproto_index_read(client, atproto_index.entries["vcs"].entries["git"], depth=2)
                if (
                    push_options.pr_repo in atproto_index.entries["vcs"].entries["git"].entries
                    and "pull_requests" in atproto_index.entries["vcs"].entries["git"].entries[push_options.pr_repo].entries
                ):
                    pull_request = {
                        "base": push_options.pr_branch,
                        "target": push_options.branch,
                        "repo": {
                            "protocol": "publicdomainrelay/index-atproto-v2@v1",
                            "data": {
                                "uri": our_atproto_index.entries["vcs"].entries["git"].entries[repo_name].post.uri,
                                "cid": our_atproto_index.entries["vcs"].entries["git"].entries[repo_name].post.cid,
                            },
                        },
                    }
                    created, cached = await atproto_index_create(
                        client,
                        atproto_index.entries["vcs"].entries["git"].entries[push_options.pr_repo].entries["pull_requests"],
                        json.dumps(pull_request),
                    )
                    if created:
                        print(f"Updated pull_request to {namespace}/{push_options.pr_repo}: {pull_request}")
