# Git over ATProto

You must install [`deno`](https://docs.deno.com/runtime/getting_started/installation/) due to profile pinned post updating not being available in the Python ATProto client APIs yet.

```bash
python -m pip install gitatp

curl -fsSL https://deno.land/install.sh | sh

git config --global user.email $USER@example.com
git config --global user.atproto $USER.atproto-pds.fqdn.example.com
python -m keyring set $USER@example.com password.$USER.atproto-pds.fqdn.example.com

python -m gitatp --repos-directory $HOME/.local/$USER-gitatp-repos

rm -rf my-repo/ && git clone http://localhost:8080/$USER.atproto-pds.fqdn.example.com/my-repo.git && cd my-repo
echo 2222 >> README.md && git add README.md && git commit -sm README.md && git push

# Create Pull Request
git push -o pr.ns=alice.atproto-pds.fqdn.example.com -o pr.branch=main
```

You can view repo files at: http://localhost:8080/$USER.atproto-pds.fqdn.example.com/my-repo/blob/HEAD/README.md

![Screenshot of web view of code](https://github.com/user-attachments/assets/b7387416-7981-4f2d-bf1c-f3ffe6095f05)

- Features
  - Push to ATProto threads of your own handle
    - **TODO** Enable federation, aka push to others repos via: https://github.com/publicdomainrelay/reference-implementation/issues/8
  - Pull from ATProto threads of any handle
- References
  - https://github.com/publicdomainrelay/reference-implementation/issues/15
  - https://github.com/publicdomainrelay/atprotobin

[![asciicast](https://asciinema.org/a/692702.svg)](https://asciinema.org/a/692702)
