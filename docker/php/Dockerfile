FROM php:8.3-fpm

RUN apt-get update && apt-get install -y git zip nano zsh iputils-ping graphviz libssl-dev libssh2-1-dev libssh2-1

WORKDIR /application
COPY ./src ./src
COPY composer.json .
COPY ./vendor ./vendor

RUN php -r "readfile('http://getcomposer.org/installer');" | php -- --install-dir=/usr/bin/ --filename=composer

RUN pecl install ssh2 && docker-php-ext-enable ssh2

RUN pecl install xdebug
RUN touch /tmp/xdebug.log
RUN chmod 0777 /tmp/xdebug.log

#PGP Encription library
RUN apt-get install -y libgpgme-dev gnupg libgpg-error-dev libassuan-dev
RUN pecl install gnupg

#Mcryp Encription library
RUN apt-get install -y libmcrypt-dev
RUN pecl install mcrypt