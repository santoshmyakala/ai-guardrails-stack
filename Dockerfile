# syntax=docker/dockerfile:1
# Build stage: install guardstack and its pinned dependencies into a virtualenv.
FROM python:3.13.18-slim-trixie AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install . \
 && /opt/venv/bin/pip uninstall -y pip setuptools

# Runtime stage: the virtualenv on a patched base, without pip or setuptools, as a non-root user.
FROM python:3.13.18-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip setuptools \
 && groupadd --system --gid 10001 guardstack \
 && useradd --system --uid 10001 --gid 10001 --no-create-home guardstack \
 && mkdir -p /var/lib/guardstack && chown 10001:10001 /var/lib/guardstack
COPY --from=build /opt/venv /opt/venv

USER 10001:10001
WORKDIR /var/lib/guardstack
ENV GUARDSTACK_AUDIT_LOG=/var/lib/guardstack/audit.jsonl
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status != 200)"
ENTRYPOINT ["guardstack"]
CMD ["serve", "--host", "0.0.0.0", "--config", "/etc/guardstack/guardstack.yml"]
