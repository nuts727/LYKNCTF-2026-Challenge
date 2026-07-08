FROM python:3.12-alpine

RUN apk add --no-cache socat \
    && adduser -D -H -s /sbin/nologin ctf

WORKDIR /app
COPY server.py ./

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=9999

USER ctf
EXPOSE 9999

CMD ["sh", "-c", "exec socat TCP-LISTEN:${PORT},reuseaddr,fork EXEC:\"python3 /app/server.py\",stderr"]
