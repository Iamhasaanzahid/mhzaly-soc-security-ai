# MHZALY SOC — dashboard image (also used for the scheduler service)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MHZALY_DB_PATH=/data/mhzaly_soc.db

WORKDIR /app

RUN groupadd --system --gid 1001 soc \
    && useradd --system --uid 1001 --gid soc --create-home soc \
    && mkdir -p /data && chown soc:soc /data

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R soc:soc /app

USER soc
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
