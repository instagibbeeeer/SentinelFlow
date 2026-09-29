FROM python:3.12-slim
WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/app.py /app/app.py
COPY common ./common
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
