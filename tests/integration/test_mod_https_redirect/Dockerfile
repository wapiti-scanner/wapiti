ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}
EXPOSE 443 80 8443 8080

RUN apt-get -y update && \
    apt-get -y install openssl -y && \
    apt-get -y clean && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    truncate -s 0 /var/log/*log

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/server.key -out /etc/apache2/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"

RUN /usr/sbin/a2enmod rewrite ssl

COPY ./apache_conf/000-default.conf /etc/apache2/sites-available/000-default.conf

# Start Apache
CMD ["apache2-foreground"]
