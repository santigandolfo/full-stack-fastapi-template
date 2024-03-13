FROM tiangolo/uvicorn-gunicorn-fastapi:python3.11

WORKDIR /app/

ENV VIRTUAL_ENV=/usr/local

COPY ./pyproject.toml /app/
COPY requirements-dev.lock /app/requirements.txt

RUN pip install uv
RUN uv pip install --no-cache -r requirements.txt


ENV PYTHONPATH=/app

COPY ./scripts/ /app/

COPY ./alembic.ini /app/

COPY ./prestart.sh /app/

COPY ./tests-start.sh /app/

COPY ./app /app/app
