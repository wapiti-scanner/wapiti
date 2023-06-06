ARG PHP_HASH_TAG=':8.1-apache'
FROM php${PHP_HASH_TAG}

RUN mv /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini &&\
    sed -i \
    -e 's/;disable_functions =/disable_functions =/' \
    -e 's/;disable_classes =/disable_classes =/' \
    -e 's/;allow_url_fopen = Off/allow_url_fopen = On/' \
    -e 's/;allow_url_include = Off/allow_url_include = On/' \
    -e 's/;enable_dl = Off/enable_dl = On/' \
    -e 's/;xmlrpc_entity_loader = Off/xmlrpc_entity_loader = On/' \
    /usr/local/etc/php/php.ini

# Let us take advantage of creating a dockerfile to also fake "/etc/network" and "/usr/etc/networks" files to disclose
RUN mkdir /usr/etc &&\
    printf "\
    default         0.0.0.0\n\
    loopback        127.0.0.0\n\
    link-local      169.254.0.0\n\
    google-dns      8.8.4.4"\
    | tee /etc/networks > /usr/etc/networks

CMD ["apache2-foreground"]
