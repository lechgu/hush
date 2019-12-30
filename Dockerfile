FROM alpine

RUN apk add --no-cache python3
RUN apk add --virtual .build-deps gcc musl-dev curl
WORKDIR /app
COPY pyproject.toml .
COPY hush.py .
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
RUN python3 $HOME/.poetry/bin/poetry build
RUN pip3 install dist/hush-0.5.1-py3-none-any.whl
RUN apk --purge del .build-deps
ENTRYPOINT  [ "hush" ]