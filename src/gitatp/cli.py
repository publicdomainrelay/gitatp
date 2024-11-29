from .git_http_backend import *

def main() -> None:
    # Ensure there is a bare Git repository for testing
    test_repo_path = os.path.join(GIT_PROJECT_ROOT, "my-repo.git")
    if not os.path.exists(test_repo_path):
        os.makedirs(GIT_PROJECT_ROOT, exist_ok=True)
        os.system(f"git init --bare {test_repo_path}")
        os.system(f"rm -rf {test_repo_path}/hooks/")
        print(f"Initialized bare repository at {test_repo_path}")

    # Start the server
    web.run_app(app, host="0.0.0.0", port=8080)
