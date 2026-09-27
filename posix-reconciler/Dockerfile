FROM python:3.13-alpine

RUN addgroup -S reconciler && adduser -S -G reconciler reconciler
WORKDIR /app
COPY reconciler.py /app/reconciler.py
RUN mkdir /state && chown reconciler:reconciler /state

USER reconciler
VOLUME ["/state"]
ENTRYPOINT ["python", "/app/reconciler.py"]
