FROM python:3.12-slim
WORKDIR /app
COPY common /app/common
COPY agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY agent/agent.py /app/agent.py
COPY agent/agent_tools.py /app/agent_tools.py
CMD ["python", "/app/agent.py"]
