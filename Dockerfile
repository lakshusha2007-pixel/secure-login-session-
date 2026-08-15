FROM php:8.2-apache

# Install required PHP extensions (mysqli, pdo_mysql, session)
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Enable Apache mod_rewrite & headers for .htaccess routing and security rules
RUN a2enmod rewrite headers

# Copy application source code into Apache document root
COPY . /var/www/html/

# Set proper ownership and permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Expose standard web port
EXPOSE 80

# Start Apache web server in foreground
CMD ["apache2-foreground"]
