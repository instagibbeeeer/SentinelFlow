FROM python:3.12-slim
WORKDIR /app
COPY event-writer/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY event-writer/writer.py ./writer.py
COPY common ./common

CMD ["python", "writer.py"]
