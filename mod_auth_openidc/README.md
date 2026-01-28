<!--
SPDX-FileCopyrightText: Copyright 2026 OP Pohjola (https://op.fi). All Rights Reserved.

SPDX-License-Identifier: LicenseRef-OpPohjolaAllRightsReserved
-->

# Authentication demo with Apache mod_auth_openidc

This directory contains an example Docker container that uses Apache mod_auth_openidc module to authenticate the user using OP Identity Service Broker's sandbox environment.

Make sure you have Docker installed. Then to build and run the container, type following commands in this directory:

```
docker build -t apachedemo .
docker run --platform linux/amd64 -p 8001:8001 -it apachedemo:latest
```

Then enter http://localhost:8001/ with your browser.

The Apache OpenID Connect module can be found here:
https://github.com/zmartzone/mod_auth_openidc

We recommend you look into it's documentation for further details on the configuration options, such as adjusting the session storage mechanism or session timeout.
  
