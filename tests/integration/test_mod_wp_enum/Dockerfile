ARG WP_HASH_TAG=":6.2.0"
FROM wordpress${WP_HASH_TAG}

ENV DEPENDENCIES "curl unzip"

# Install zip utility
RUN apt-get update -y &&\
    apt-get install ${DEPENDENCIES} -y --no-install-recommends &&\ 
    apt-get -y autoremove &&\
    apt-get clean 

# Pre-moving files for a lightest image
RUN rm -rf /var/www/html/* &&\ 
    mv /usr/src/wordpress/* /var/www/html/

# Install Contact Form 7 plugin
#         Yoast SEO plugin
#         Jetpack plugin
#         WorFence plugin
#         WPForms plugin
#         OceanWP Theme
RUN echo 'https://downloads.wordpress.org/plugin/contact-form-7.5.7.5.zip' \
    'https://downloads.wordpress.org/plugin/wordpress-seo.19.7.1.zip' \
    'https://downloads.wordpress.org/plugin/jetpack.11.9.zip' \
    'https://downloads.wordpress.org/plugin/wordfence.7.5.0.zip' \
    'https://downloads.wordpress.org/plugin/wpforms-lite.1.7.5.3.zip' \
    'https://downloads.wordpress.org/theme/oceanwp.3.4.3.zip' \
    | xargs -P 6 -I {} sh -c 'curl -o /tmp/$(basename {} | cut -d'.' -f1).zip -SL {} && \
    unzip -o /tmp/$(basename {} | cut -d'.' -f1) -d /var/www/html/wp-content/$(echo {} | cut -d'/' -f4)s/ && \
    rm /tmp/$(basename {} | cut -d'.' -f1).zip'



# Start Apache
CMD ["apache2-foreground"]
