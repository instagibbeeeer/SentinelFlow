FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent_tools.py .
COPY agent.py .
CMD ["python", "agent.py"]
