FROM python:3.11-slim

WORKDIR /tool
COPY tool_server.py /tool/tool_server.py

EXPOSE 9000
ENV TOOL_PORT=9000
CMD ["python", "/tool/tool_server.py"]
