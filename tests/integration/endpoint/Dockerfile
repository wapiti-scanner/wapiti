FROM php@sha256:5d5f0dbea68afab7e6fa7649fb818e078680e338a3265ec5cf237a6a791dd471 
EXPOSE 80

COPY ./endpoint/* /var/www/html

RUN /usr/sbin/a2enmod rewrite

RUN chown -R www-data:www-data /var/www/html &&\
    chmod -R g+w /var/www/html

CMD ["apache2-foreground"]
