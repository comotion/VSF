# Braindead Makefile. Feel free to improve.
# Copyright (c) 2009 Redpill Linpro AS
# Author: Kristian Lyngstol <kristian@redpill-linpro.com
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Basic logic:
#  build/variables.vcl and VARIABLES allows us to do easy testing of
#  whether we properly clean up (aka: check). Ruletest is fairly dirty.

all: build/variables.vcl check

check:
	@../tools/check_variables
	@echo "Check passed: No unknown variables found"

ruletest:
	@../tools/rule_test */*vcl| bash

clean:
	rm -r build

build/variables.vcl: VARIABLES
	@mkdir -p build
	@echo -n "Generating build/variables.vcl: "
	@../tools/generate_variables
	@echo "done"







