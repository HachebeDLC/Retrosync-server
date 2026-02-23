FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for psycopg2 and cryptography
RUN apt-get update && apt-get install -y 
    build-essential 
    libpq-dev 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Create storage directory
RUN mkdir -p /app/storage

EXPOSE 8000

CMD ["python", "main.py"]
