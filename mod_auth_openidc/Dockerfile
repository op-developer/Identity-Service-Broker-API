FROM debian:buster
EXPOSE 8001

WORKDIR /var/www/html
ADD https://github.com/zmartzone/mod_auth_openidc/releases/download/v2.4.4.1/libapache2-mod-auth-openidc_2.4.4.1-1.buster+1_amd64.deb /var/tmp/
RUN apt-get update &&  \
	apt-get install -y apache2 apache2-utils lsb-base mime-support perl procps libcjose0 libcurl4 libhiredis0.14 && \
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

