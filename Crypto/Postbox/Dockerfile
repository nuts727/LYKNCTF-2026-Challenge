FROM python:3.12-alpine

RUN adduser -D -H -s /sbin/nologin ctf

WORKDIR /app
COPY server.py ./

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=9999

USER ctf
EXPOSE 9999

CMD ["sh", "-c", "exec python3 /app/server.py 0.0.0.0 ${PORT}"]
