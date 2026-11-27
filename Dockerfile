# One image that serves the dashboard and the API together (used by render.yaml).
# Build from the repository root:  docker build -t threatlens .
FROM node:22-alpine AS frontend
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ML_MODEL_DIR=/app/ml_models FRONTEND_DIST=/app/frontend_dist
WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY ml/models/ /app/ml_models/
COPY --from=frontend /app/dist /app/frontend_dist
RUN DJANGO_SECRET_KEY=build-only python manage.py collectstatic --noinput \
 && useradd --system --no-create-home threatlens \
 && chown -R threatlens /app
USER threatlens

EXPOSE 10000
# PORT is set by the host (Render uses 10000). Migrate and create the first users, then serve.
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py bootstrap_demo && exec gunicorn config.wsgi:application --bind 0.0.0.0:${PORT:-10000} --workers 2 --timeout 60"]
