ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}

RUN /usr/sbin/a2enmod rewrite 

CMD ["apache2-foreground"]
