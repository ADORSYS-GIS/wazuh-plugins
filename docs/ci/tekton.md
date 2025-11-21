# Building cache and builders with Tekton

You can run the same cache image build and native builder pipelines on any Tekton cluster. Use the examples below as a starting point; adjust registry names, secrets, and triplets to match your environment.

## Prerequisites

- Tekton Pipelines installed on your cluster.
- A registry secret for GHCR (or your target registry) and a ServiceAccount that references it:
  ```bash
  kubectl create secret docker-registry ghcr-auth \
    --docker-server=ghcr.io \
    --docker-username=<github-username> \
    --docker-password=<github-token>

  cat <<'YAML' | kubectl apply -f -
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: builders-sa
  secrets:
    - name: ghcr-auth
  YAML
  ```
- A workspace (PVC) named `shared-workspace` or swap for your own.

## Pipeline: build the cache image (kaniko)

This builds `.github/docker/cache.Dockerfile` once and pushes `cache-builders` to GHCR. Uses the Tekton catalog `git-clone` task and kaniko to avoid docker-in-docker.

```yaml
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: build-cache-image
spec:
  workspaces:
    - name: shared
  params:
    - name: repo
      default: https://github.com/<org>/wazuh-plugins.git
    - name: revision
      default: main
    - name: image
      default: ghcr.io/<org>/wazuh-plugins/cache-builders
  tasks:
    - name: fetch
      taskRef:
        name: git-clone
        kind: ClusterTask
      workspaces:
        - name: output
          workspace: shared
      params:
        - name: url
          value: $(params.repo)
        - name: revision
          value: $(params.revision)
        - name: submodules
          value: "true"
    - name: build-and-push
      runAfter: [fetch]
      workspaces:
        - name: source
          workspace: shared
      taskSpec:
        params:
          - name: image
        workspaces:
          - name: source
        steps:
          - name: kaniko
            image: gcr.io/kaniko-project/executor:latest
            workingDir: $(workspaces.source.path)
            args:
              - --context=$(workspaces.source.path)
              - --dockerfile=.github/docker/cache.Dockerfile
              - --destination=$(params.image):latest
              - --destination=$(params.image):$(params.revision)
              - --snapshotMode=time
              - --compressed-caching=false
            env:
              - name: "DOCKER_CONFIG"
                value: "/tekton/home/.docker"
  serviceAccountName: builders-sa
```

Create a `PipelineRun` to execute it:
```bash
cat <<'YAML' | kubectl apply -f -
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: cache-build-
spec:
  pipelineRef:
    name: build-cache-image
  workspaces:
    - name: shared
      persistentVolumeClaim:
        claimName: shared-workspace
  serviceAccountName: builders-sa
YAML
```

## Pipeline: run a builder (Suricata/Yara) in Tekton

This reuses the cache image as the step image, runs `run_builder.py`, and packages artifacts. Triplets and builder names are parameters so you can trigger multiple `PipelineRun`s for different targets.

```yaml
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: build-builder
spec:
  workspaces:
    - name: shared
  params:
    - name: repo
      default: https://github.com/<org>/wazuh-plugins.git
    - name: revision
      default: main
    - name: builder
      default: suricata   # or yara
    - name: triplet
      default: linux-amd64
    - name: cache_image
      default: ghcr.io/<org>/wazuh-plugins/cache-builders:latest
  tasks:
    - name: fetch
      taskRef:
        name: git-clone
        kind: ClusterTask
      workspaces:
        - name: output
          workspace: shared
      params:
        - name: url
          value: $(params.repo)
        - name: revision
          value: $(params.revision)
        - name: submodules
          value: "true"
    - name: build
      runAfter: [fetch]
      workspaces:
        - name: source
          workspace: shared
      taskSpec:
        params:
          - name: builder
          - name: triplet
          - name: cache_image
        workspaces:
          - name: source
        steps:
          - name: build
            image: $(params.cache_image)
            workingDir: $(workspaces.source.path)
            env:
              - name: PIPELINE_COMMIT
                value: $(params.revision)
              - name: PIPELINE_REF
                value: $(params.revision)
              - name: PIPELINE_REPO
                value: $(params.repo)
            script: |
              #!/usr/bin/env bash
              set -euo pipefail
              python3 -m venv .venv
              source .venv/bin/activate
              pip install -r .github/workflows/venv-requirements.txt
              export PIPELINE_VERSION="$(cat builders/$(params.builder)/version.txt)"
              python .github/scripts/run_builder.py --artifact-triplet $(params.triplet) builders/$(params.builder)/config.yaml
              python .github/scripts/package_artifacts.py $(params.builder) $(params.triplet)
  serviceAccountName: builders-sa
```

Example `PipelineRun`:
```bash
cat <<'YAML' | kubectl apply -f -
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: build-suricata-
spec:
  pipelineRef:
    name: build-builder
  params:
    - name: builder
      value: suricata
    - name: triplet
      value: linux-amd64
  workspaces:
    - name: shared
      persistentVolumeClaim:
        claimName: shared-workspace
  serviceAccountName: builders-sa
YAML
```

Artifacts are written under `artifacts/<builder>-<version>-<triplet>/` in the workspace. Upload them to your artifact store (S3/MinIO/PVC) with an additional task if desired.
