# The following hash corresponds to the image php:8.1.18-apache
# php@sha256:5d5f0dbea68afab7e6fa7649fb818e078680e338a3265ec5cf237a6a791dd471
# it can be found here: https://hub.docker.com/layers/library/php/8.1.18-apache/images/sha256-5d5f0dbea68afab7e6fa7649fb818e078680e338a3265ec5cf237a6a791dd471?context=explore

FROM php@sha256:5d5f0dbea68afab7e6fa7649fb818e078680e338a3265ec5cf237a6a791dd471
EXPOSE 443 80 

RUN apt-get update -y && \
    apt-get install openssl -y && \
    apt-get clean -yq && \
    apt-get -y autoremove -yq && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    truncate -s 0 /var/log/*log

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/server.key -out /etc/apache2/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"

RUN /usr/sbin/a2enmod rewrite ssl

COPY ./apache_conf/000-default.conf /etc/apache2/sites-available/000-default.conf

# Start Apache
CMD ["apache2-foreground"]
