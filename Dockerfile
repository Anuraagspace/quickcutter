# QuickCutter AI Studio - Docker deployment for Railway & Cloud
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg nodejs ca-certificates bzip2 fonts-noto-core fonts-noto-cjk \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY LICENSE README.md AGENTS.md ./
COPY studio ./studio
COPY web ./web

ENV QUICKCUTTER_DATA=/data \
    QUICKCUTTER_HOST=0.0.0.0 \
    QUICKCUTTER_TRUST_PROXY=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8765

CMD ["python", "-m", "studio.server"]
