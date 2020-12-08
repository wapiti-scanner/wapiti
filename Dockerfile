FROM debian:buster-slim as build

ENV DEBIAN_FRONTEND=noninteractive \
  LANG=en_US.UTF-8

WORKDIR /usr/src/app

RUN apt update \
  && apt install python3 python3-setuptools ca-certificates -y \
  && apt clean -yq \
  && apt autoremove -yq \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
  && truncate -s 0 /var/log/*log

COPY . .

RUN python3 setup.py install

FROM debian:buster-slim

ENV DEBIAN_FRONTEND=noninteractive \
  LANG=en_US.UTF-8 \
  PYTHONDONTWRITEBYTECODE=1

RUN apt update \
  && apt install python3 python3-setuptools -y \
  && apt clean -yq \
  && apt autoremove -yq \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
  && truncate -s 0 /var/log/*log

COPY --from=build /usr/local/lib/python3.7/dist-packages/ /usr/local/lib/python3.7/dist-packages/
COPY --from=build /usr/local/bin/wapiti /usr/local/bin/wapiti-getcookie /usr/local/bin/

CMD ["wapiti"]
