# Git over ATProto

You must install [`deno`](https://docs.deno.com/runtime/getting_started/installation/) due to profile pinned post updating not being available in the Python ATProto client APIs yet.

```bash
python -m pip install gitatp

curl -fsSL https://deno.land/install.sh | sh

git config --global user.email $USER@example.com
git config --global user.atproto $USER.atproto-pds.fqdn.example.com
python -m keyring set $USER@example.com password.$USER.atproto-pds.fqdn.example.com

python -m gitatp --repos-directory $HOME/.local/$USER-gitatp-repos
```

- References
  - https://github.com/publicdomainrelay/reference-implementation/issues/15

[![asciicast](https://asciinema.org/a/692702.svg)](https://asciinema.org/a/692702)
