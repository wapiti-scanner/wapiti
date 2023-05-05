FROM wordpress:latest

# Install zip utility
RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get dist-upgrade -y \
    && apt-get -y autoremove \
    && apt-get clean 

RUN apt-get install zip unzip -y  

# Install Contact Form 7 plugin
RUN curl -o /tmp/contact-form-7.zip -SL https://downloads.wordpress.org/plugin/contact-form-7.latest-stable.zip \
    && unzip -q /tmp/contact-form-7.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/contact-form-7.zip

# Install Yoast SEO plugin
RUN curl -o /tmp/yoast-seo.zip -SL https://downloads.wordpress.org/plugin/wordpress-seo.latest-stable.zip \
    && unzip -q /tmp/yoast-seo.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/yoast-seo.zip

# Install Jetpack plugin
RUN curl -o /tmp/jetpack.zip -SL https://downloads.wordpress.org/plugin/jetpack.latest-stable.zip \
    && unzip -q /tmp/jetpack.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/jetpack.zip

# Install WooCommerce plugin
RUN curl -o /tmp/woocommerce.zip -SL https://downloads.wordpress.org/plugin/woocommerce.latest-stable.zip \
    && unzip -q /tmp/woocommerce.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/woocommerce.zip

# Install WPForms plugin
RUN curl -o /tmp/wpforms.zip -SL https://downloads.wordpress.org/plugin/wpforms-lite.latest-stable.zip \
    && unzip -q /tmp/wpforms.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/wpforms.zip

# Install W3 Total Cache plugin
RUN curl -o /tmp/w3-total-cache.zip -SL https://downloads.wordpress.org/plugin/w3-total-cache.latest-stable.zip \
    && unzip -q /tmp/w3-total-cache.zip -d /usr/src/wordpress/wp-content/plugins\
    && rm /tmp/w3-total-cache.zip

# Install Akismet Anti-Spam plugin
RUN curl -o /tmp/akismet.zip -SL https://downloads.wordpress.org/plugin/akismet.latest-stable.zip \
    && unzip -oq /tmp/akismet.zip -d /usr/src/wordpress/wp-content/plugins \
    && rm /tmp/akismet.zip

# Set permissions
# RUN chown -R www-data:www-data /usr/src/wordpress/wp-content/plugins
 
# Set the entrypoint script to the default WordPress entrypoint
# ENTRYPOINT ["docker-entrypoint.sh"]

# Start Apache
CMD ["apache2-foreground"]
