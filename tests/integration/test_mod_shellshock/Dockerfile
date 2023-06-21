ARG HTTPD_HASH_TAG='@sha256:760413d133979e7cc5ced07d8c323e7b68bb48b4e114f8898c2f2d6af82e2424'
FROM httpd${HTTPD_HASH_TAG}

COPY  packages /packages
COPY ./html/src/index.html /usr/local/apache2/htdocs/index.html
COPY ./vuln.cgi /usr/local/apache2/cgi-bin/vuln.cgi 

RUN apt-get -y update &&\
    apt-get -y install -f /packages/* curl --allow-downgrades &&\
    apt-get -y clean &&\
    apt-get -y autoremove &&\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* &&\
    truncate -s 0 /var/log/*log

# Enabling module and setting some permissions
RUN sed -i 's/#LoadModule cgid_module modules\/mod_cgid.so/LoadModule cgid_module modules\/mod_cgid.so/' \
    /usr/local/apache2/conf/httpd.conf &&\
    chown www-data /usr/local/apache2/htdocs/index.html /usr/local/apache2/cgi-bin/vuln.cgi &&\
    chmod +x /usr/local/apache2/cgi-bin/vuln.cgi 

STOPSIGNAL SIGWINCH
EXPOSE 80
CMD ["httpd-foreground"]