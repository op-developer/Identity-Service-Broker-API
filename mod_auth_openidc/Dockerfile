FROM --platform=linux/amd64 debian:bookworm
EXPOSE 8001

WORKDIR /var/www/html
ADD https://github.com/OpenIDC/mod_auth_openidc/releases/download/v2.4.15.3/libapache2-mod-auth-openidc_2.4.15.3-1.bookworm_amd64.deb /var/tmp/

RUN apt-get update &&  \
	apt-get install -y apache2 apache2-utils libcjose0 libcurl4 libhiredis0.14 libjansson4 libpcre2-8-0 libssl3 && \
	dpkg -i /var/tmp/*.deb; \
	mkdir /var/www/html/secured /etc/apache2/keys && \
	a2enmod auth_openidc && \
	a2enmod cgi && \
	echo "Listen 8001" >> /etc/apache2/ports.conf
COPY index.html ./
COPY index.cgi ./secured/
COPY site-config.conf /etc/apache2/sites-enabled/000-default.conf
ADD https://github.com/op-developer/Identity-Service-Broker-API/raw/master/sandbox-sp-signing-key.pem /etc/apache2/keys/
ADD https://github.com/op-developer/Identity-Service-Broker-API/raw/master/sandbox-sp-encryption-key.pem /etc/apache2/keys/

CMD apachectl -D FOREGROUND

