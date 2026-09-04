FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ULPF application
COPY ulpf/ ./ulpf/
COPY plugins/ ./plugins/
COPY models/ ./models/
COPY run.py .
COPY model.py .

# Create output directory
RUN mkdir -p /app/out

# ULPF CLI
ENTRYPOINT ["python", "run.py"]
