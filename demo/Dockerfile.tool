FROM python:3.11-slim
WORKDIR /app
COPY demo/tool/tool_server.py /app/tool_server.py
EXPOSE 9000
ENV TOOL_PORT=9000
CMD ["python", "/app/tool_server.py"]
