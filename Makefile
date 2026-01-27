# SPDX-FileCopyrightText: Copyright 2026 OP Pohjola (https://op.fi). All Rights Reserved.
#
# SPDX-License-Identifier: LicenseRef-OpPohjolaAllRightsReserved

.PHONY: pdf

pdf:
	test -d node_modules/markdown-pdf || npm install markdown-pdf
	rm -Rf build && mkdir build
	git log -1 --format=%ci | cut -d ' ' -f 1 > build/date.txt
	./node_modules/markdown-pdf/bin/markdown-pdf -h runnings.js README.md

