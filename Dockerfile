FROM python:3.11-slim-bullseye

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot/ ./bot/

# Ensure data directory exists for SQLite
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "bot.main"]
