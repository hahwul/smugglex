FROM python:3.12-slim

WORKDIR /app
# Pure standard-library scripts — no pip dependencies.
COPY backend.py frontend.py ./

# Overridden per service in docker-compose.yml.
CMD ["python", "frontend.py"]
