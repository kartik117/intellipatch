FROM python:3.11-slim
WORKDIR /app

# Trivy needs its own binary -- not a pip package. Installed via Aqua
# Security's official install script rather than added as a system
# package repo, since slim Debian images don't have one configured.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
       | sh -s -- -b /usr/local/bin \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
COPY models ./models
RUN pip install --no-cache-dir .

# Warm Trivy's vulnerability DB at build time so the first real `docker
# compose up` scan isn't the one paying a ~100MB download -- the same
# DB download that made the very first local scan in this project slow.
RUN trivy image --download-db-only

# Overridden per-service in docker-compose.yml.
CMD ["uvicorn", "intellipatch.services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
