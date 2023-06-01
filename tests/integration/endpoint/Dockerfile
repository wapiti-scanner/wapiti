ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}
EXPOSE 80

COPY ./endpoint/* /var/www/html

RUN /usr/sbin/a2enmod rewrite

RUN chown -R www-data:www-data /var/www/html &&\
    chmod -R g+w /var/www/html

CMD ["apache2-foreground"]
