FROM python:3.12-slim

RUN useradd -r -u 10001 -m honeypot \
 && mkdir -p /data && chown honeypot /data
WORKDIR /app
COPY honeypot.py .

USER honeypot
EXPOSE 7860
VOLUME ["/data"]
ENTRYPOINT ["python", "-u", "honeypot.py", "--data-dir", "/data", "--port", "7860"]
