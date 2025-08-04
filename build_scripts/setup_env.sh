# Set up Needed Variables
export ARTIFACTORY_USERNAME="$(get_env ARTIFACTORY_USERNAME)"
export ARTIFACTORY_TOKEN="$(get_env ARTIFACTORY_TOKEN)"
export DOCKER_REGISTRY="$(get_env DOCKER_REGISTRY)"
export DOCKER_USER="$(get_env DOCKER_USER)"
export DOCKER_PASS="$(get_env DOCKER_PASS)"
export GITHUB_TOKEN="$(get_env GITHUB_TOKEN)"
export GITHUB_USER="$(get_env GITHUB_USER)"
export SPS_EVENT_TYPE="$(get_env SPS_EVENT_TYPE)"

# Configure Environment
echo -e "machine github.ibm.com\n  login $GITHUB_TOKEN" >> ~/.netrc
chmod 600 ~/.netrc
git config --global --add safe.directory $WORKSPACE/$(load_repo app-repo path)
# Output Paremeters
echo "Current branch : $GIT_BRANCH"
echo "Building commit $GIT_COMMIT"

# Login to root artifactory (to cover both base images and build image)
docker login docker-na-public.artifactory.swg-devops.com -u ARTIFACTORY_USERNAME -p ARTIFACTORY_TOKEN
