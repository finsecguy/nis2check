FROM python:3.12-slim

# PDF rendering (WeasyPrint) needs Pango; Carlito is a free font metric-compatible with Calibri
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
    fonts-crosextra-carlito fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 nis2
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY nis2check ./nis2check
RUN pip install --no-cache-dir ".[web]"

ENV NIS2_DATA_DIR=/data \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data && chown nis2:nis2 /data
VOLUME ["/data"]
USER nis2
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

# One worker keeps the built-in scheduler single; threads handle concurrent users.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:8080", \
     "--access-logfile", "-", "nis2check.web:create_app()"]
