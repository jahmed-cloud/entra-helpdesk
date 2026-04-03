FROM python:3.11-slim-bullseye

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app

EXPOSE 8000

# Use Gunicorn for a production-ready WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--chdir", "/usr/src/app/app", "app:app"]
