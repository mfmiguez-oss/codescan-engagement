# One image, both clouds, both roles.
#
# The provider is chosen by environment at run time and never baked in, so the
# same digest is promotable from dev to prod and from Azure to AWS without a
# rebuild. The same image serves the batch job and the control plane; which one
# it becomes is the command, not the contents.
#
# The build is hermetic: every dependency comes from a public index or from the
# vendored workspace in this repo, so it never reaches a private repository and
# never needs build-time credentials.
FROM python:3.12-slim AS base

# git is a runtime dependency: the workspace clones the target under review.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY vendor ./vendor

# Both provider extras and the control plane, because one image serves every
# role and the lazy imports mean the unused ones are never loaded at run time.
# `api` in particular is not optional here: the control-plane container's
# command is `uvicorn`, and an image without it builds cleanly and then fails
# to start.
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir ".[foundry,bedrock,api]" \
 && python -m pip install --no-cache-dir ./vendor/openhack

# Non-root. The container reads source under review — code that is, by
# definition, untrusted — so it must not run with more privilege than reading
# and writing its own workspace requires.
RUN useradd --create-home --uid 10001 engagement

# The workspace root OpenHack resolves against: the vendored expert manifests,
# prompt templates, and schemas. Baked rather than mounted so the image can
# actually run a scan on its own; `runs/` underneath it is where the mutable
# per-run state goes, which is why *that* is the volume and /workspace is not.
# Mounting over /workspace itself would shadow the methodology and leave a
# container that starts and then has no experts to route to.
ENV OPENHACK_ROOT=/workspace
RUN set -eux; \
    mkdir -p /workspace/runs /artifacts; \
    for tree in agents templates config; do \
      cp -r "/app/vendor/openhack/$tree" "/workspace/$tree"; \
    done; \
    test -d /workspace/agents/experts; \
    test -f /workspace/templates/scenario-prompt.md; \
    chown -R engagement:engagement /workspace /artifacts

USER engagement

# Only the mutable parts are volumes. The methodology stays in the image.
VOLUME ["/workspace/runs", "/artifacts"]

ENTRYPOINT ["engagement"]
CMD ["--help"]
