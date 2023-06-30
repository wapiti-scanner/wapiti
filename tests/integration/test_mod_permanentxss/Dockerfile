ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}

RUN touch /var/www/html/messages.txt &&\
    chown www-data /var/www/html/messages.txt &&\
    chmod 777 /var/www/html/messages.txt
    