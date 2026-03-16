FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DRIFTWATCH_HOME=/data
ENV DRIFTWATCH_HOST=0.0.0.0
ENV DRIFTWATCH_PORT=8484

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

RUN chmod +x /app/scripts/demo-entrypoint.sh

EXPOSE 8484

ENTRYPOINT ["/app/scripts/demo-entrypoint.sh"]
