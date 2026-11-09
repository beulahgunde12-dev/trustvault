FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TV_ENV=prod TV_DB=/data/trustvault.db TV_STORAGE=/data/files
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m app && mkdir -p /data && chown -R app /data /srv
USER app
VOLUME /data
EXPOSE 8000
# TV_AUDIT_KEY and TV_SEED_PASSWORD must be supplied at run time.
CMD ["sh", "-c", "python -m app.seed && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
