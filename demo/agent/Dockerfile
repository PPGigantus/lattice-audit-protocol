FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates
WORKDIR /app
COPY demo/agent/run.sh /app/run.sh
RUN chmod +x /app/run.sh
ENTRYPOINT ["/app/run.sh"]
