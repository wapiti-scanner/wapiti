# This wordpress image refers to the 6.2.0 tag, it can be found here:
# https://hub.docker.com/layers/library/wordpress/6.2.0/images/sha256-c3d6df13e49ed4039fbbe5bd1ec172b166a7a4df603716fd06f5bd66b7e60f90?context=explore

FROM wordpress@sha256:c3d6df13e49ed4039fbbe5bd1ec172b166a7a4df603716fd06f5bd66b7e60f90

ENV DEPENDENCIES "curl unzip"

# Install zip utility
RUN apt-get update -y &&\
    apt-get install ${DEPENDENCIES} -y &&\  
    apt-get dist-upgrade -y &&\
    apt-get upgrade -y &&\
    apt-get -y autoremove &&\
    apt-get clean 


# Install Contact Form 7 plugin
RUN su -s /bin/sh www-data -c 'curl -o /tmp/contact-form-7.zip -SL https://downloads.wordpress.org/plugin/contact-form-7.5.7.5.zip &&\
    unzip -o /tmp/contact-form-7.zip -d /usr/src/wordpress/wp-content/plugins &&\
    rm /tmp/contact-form-7.zip'

# Install Yoast SEO plugin
RUN su -s /bin/sh www-data -c 'curl -o /tmp/yoast-seo.zip -SL https://downloads.wordpress.org/plugin/wordpress-seo.19.7.1.zip &&\
    unzip -o /tmp/yoast-seo.zip -d /usr/src/wordpress/wp-content/plugins  &&\
    rm /tmp/yoast-seo.zip'

# Install Jetpack plugin
RUN su -s /bin/sh www-data -c 'curl -o /tmp/jetpack.zip -SL https://downloads.wordpress.org/plugin/jetpack.11.9.zip &&\
    unzip -o /tmp/jetpack.zip -d /usr/src/wordpress/wp-content/plugins &&\
    rm /tmp/jetpack.zip'

# Install WorFence plugin
RUN su -s /bin/sh www-data -c 'curl -o /tmp/wordfence.zip -SL https://downloads.wordpress.org/plugin/wordfence.7.5.0.zip &&\
    unzip -o /tmp/wordfence.zip -d /usr/src/wordpress/wp-content/plugins &&\
    rm /tmp/wordfence.zip'

# Install WPForms plugin
RUN su -s /bin/sh www-data -c 'curl -o /tmp/wpforms.zip -SL https://downloads.wordpress.org/plugin/wpforms-lite.1.7.5.3.zip &&\
    unzip -o /tmp/wpforms.zip -d /usr/src/wordpress/wp-content/plugins &&\
    rm /tmp/wpforms.zip'

# Install OceanWP Theme
RUN su -s /bin/sh www-data -c 'curl -o /tmp/oceanwp.zip -SL https://downloads.wordpress.org/theme/oceanwp.3.4.3.zip &&\
    unzip -o /tmp/oceanwp.zip -d /usr/src/wordpress/wp-content/themes &&\
    rm /tmp/oceanwp.zip'

# Start Apache
CMD ["apache2-foreground"]
