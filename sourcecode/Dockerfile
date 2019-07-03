from alpine:latest

RUN apk add --no-cache musl-dev python3-dev openssl-dev libffi-dev gcc \
    # Pillow dependencies
    jpeg-dev \
    zlib-dev \
    freetype-dev \
    lcms2-dev \
    openjpeg-dev \
    tiff-dev \
    tk-dev \
    tcl-dev \
    harfbuzz-dev \
    fribidi-dev \
    && pip3 install --upgrade pip

ENV LIBRARY_PATH=/lib:/usr/lib

WORKDIR /app

COPY . /app

RUN pip --no-cache-dir install -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python3"]
CMD ["run.py"]
