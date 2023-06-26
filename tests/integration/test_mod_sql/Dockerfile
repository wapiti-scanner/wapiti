ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}

COPY ./php/db_init.php /var/www/db_init.php

RUN php /var/www/db_init.php &&\
    chown www-data /var/www/target.sqlite

ENTRYPOINT ["apache2-foreground"]
