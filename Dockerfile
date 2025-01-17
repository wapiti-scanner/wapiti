FROM python:3.13-slim AS build

ENV DEBIAN_FRONTEND=noninteractive \
  LANG=en_US.UTF-8

WORKDIR /usr/src/app

COPY . .

RUN pip3 install . --break-system-packages

FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
  LANG=en_US.UTF-8 \
  PYTHONDONTWRITEBYTECODE=1 \
  OPENSSL_CONF='/etc/wapiti/openssl_conf'

COPY --from=build /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=build /usr/local/bin/wapiti /usr/local/bin/wapiti-getcookie /usr/local/bin/
COPY --chmod=644 openssl_conf /etc/wapiti/

ENTRYPOINT ["wapiti"]
