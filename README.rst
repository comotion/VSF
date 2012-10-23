=========================
Varnish Security Firewall
=========================

This is work in progress just like any security app should be.
Use at your own discretion.

The Varnish Security Firewall (VSF) is a Web Application Firewall (WAF)
written using the Varnish Control Language (VCL) and a sprinkling of
Varnish Modules (vmods).

VSF aims to provide:
 - A standardized framework for security-related filters
 - Several core rule-sets
 - A limited set of default 'handlers', for instance CGI scripts to call
   upon when Bad Stuff happens.

This is done mainly by using clever VCL, and with as little impact on
normal operation as possible. The incident handlers can be CGI-like
scripts on a backend.

Quick Start
===========

To use VSF you will need the parsereq, shield, throttle and urlcode vmods,
which in turn require the Varnish 3.x source code to compile and run.

Build Varnish
-------------

::

 build-essential libpcre3-dev
 wget http://repo.varnish-cache.org/source/varnish-3.0.3.tar.gz
 tar xf varnish-3.0.3.tar.gz && cd varnish-3.0.3 && ./configure
 make -j3 && make install
 cd -

then

Build VMods
-----------

::

   for mod in parsereq urlcode shield throttle; do
      cd libvmod-$mod
      ./autogen.sh && VARNISHSRC=../varnish-3.0.3 ./configure && make -j3
      make install
      cd -
   done

now symlink the vcl directory into /etc/varnish/security

::

  cd /etc/varnish && ln -s /PATH/TO/VSF/vcl security

then you edit your default.vcl and add this line near the top:

::

	include "/etc/varnish/security/vsf.vcl";

At this point, you should only need to reload your varnish configuration.

You may want to modify config.vcl to fit your needs. 
Remember that paths must be hardcoded and absolute.

The Architecture
================

VSF works by including all rulesets, then defining a number of
standard functions. Each rule  will set X-VSF-Severity = "N", where N is the
severity, and call sec_handler which in turn typically calls error or some other handler.

Handlers
========

The general concept is that VSF  either throws an error 
(vcl_error) of some kind, which can return a redirect the client,
or do any other synthetic response, or VSF can log, 
rewrite the original request and send it to a backend
designed to do more clever things, like:

* Block the client in a firewall
* Log the event
* Test-run the code.
* Paint you a pretty picture...

There are several handlers defined and you can set the default handler in handlers.vcl.
The default handler rejects detected malicious traffic.

Also you may write your own handler, see handlers.vcl

Known Issues
============

Let us know! http://github.com/comotion/VSF/issues

References
==========

This work is based on the work of:

* VFW                           https://github.com/scarpellini/VFW
 * by Eduardo S. Scarpellini
* Security.VCL                  https://github.com/comotion/security.vcl
 * by Kristian Lyngstøl, Edward B. Fjellskål and Kacper Wysocki

As well as the authors of the following VMODs:

* Syohei 'xcir' Tanaka:         https://github.com/xcir/libvmod-parsereq.git
* N. 'nand2' Deschildre:        https://github.com/nand2/libvmod-throttle.git
* Rogier 'DocWilco' Mulhuijzen: https://github.com/fastly/libvmod-urlcode.git
* Varnish Software ('martin'):  https://github.com/varnish/libvmod-shield.git

and the Varnish Cache by Poul-Henning Kamp, of course ;-)

Future Work
===========

Unicode codepoints must be normalized to the shortest-byte representation
to effectively combat WAF evasion. 

* http://www.symantec.com/connect/articles/ids-evasion-unicode
 * solution: http://www.public-software-group.org/utf8proc
 * http://www.public-software-group.org/pub/projects/utf8proc/v1.1.5/utf8proc-v1.1.5.tar.gz

Write a handler to redirect triggered requests to a honeypot rather than bugging out.
A handler could also do signature-based recognition of the client/attacker.

