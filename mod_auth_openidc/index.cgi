#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2026 OP Pohjola (https://op.fi). All Rights Reserved.
#
# SPDX-License-Identifier: LicenseRef-OpPohjolaAllRightsReserved

echo "Content-Type: text/html"
echo

echo "<html><head><title>Secured part of the service</title></head>"
echo "<body><h1>Authenticated page</h1>"
echo "<p>This page requires authentication. Here are the details of the current user (given to the service as environment variables by mod_auth_openidc):</p><pre>"
set | grep OIDC
echo "</pre></body></html>"

# In real life please do not use shell scripts to write websites. This is just a quick demo showing the principle.


