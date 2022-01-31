=========================
Varnish Security Firewall
=========================

The Varnish Security Firewall is a Web Application Firewall written
using the Varnish Control Language and a varnish module.

This is work in progress just like any security app should be.
Use at your own discretion.

VSF aims to provide:
 - A standardized framework for security-related filters
 - Several core rule-sets
 - A limited set of default 'handlers', for instance CGI scripts to call
   upon when Bad Stuff happens.

This is done mainly by using clever VCL, and with as little impact
on normal cache operation as possible. The incident handlers can
be CGI-like scripts on a backend.

.. image:: https://github.com/comotion/VSF/actions/workflows/ci.yml/badge.svg?branch=6.6
    :target: https://github.com/comotion/VSF/actions

Quick Start
===========

To use VSF you will need the vsf vmod, as well as Varnish 6.6.x.
Start by installing Varnish 6.6.2 as per
https://varnish-cache.org/releases/rel6.6.2.html

Install instructions vary by OS and distro, but are roughly::


  # install build dependencies, ubuntu/debian edition
  apt-get install libvarnishapi-dev autoconf libtool pkgconfig python-docutils

  # install build dependencies, centos/rhel6 edition
  yum install varnish-libs-devel autoconf libtool pkgconfig python-docutils

  # build vmods
  make

  # install vmods & vcl
  make install

then you edit your default.vcl and add this line near the top::

  include "/etc/varnish/security/vsf.vcl";

If you want to add VCL before VSF does its magic but after imports
and backends, add it to `security/local.vcl`,

At this point, you should only need to reload your varnish configuration.

You may want to modify config.vcl to fit your needs. 

The Architecture
================

VSF works by including all rulesets, then defining a number of
standard functions. Each rule  will set X-VSF-Severity = "N", where
N is the severity, and call sec_handler which in turn typically
calls error or some other handler.

Handlers
========

The general concept is that VSF either throws an error of some kind,
which can return a redirect the client, or do any other synthetic
response, or VSF can log, rewrite the original request and send it
to a backend designed to do more clever things, like:

* Block the client in a firewall
* Log the event
* Test-run the code.
* Paint you a pretty picture...

There are several handlers defined and you can set the default
handler in handlers.vcl.
The default handler rejects detected malicious traffic.

Also you may write your own handler, see handlers.vcl

Known Issues
============

VSF uses the workspace to store the request, and the default is
64k, for request headers and body.

If you are receiving large POST or PUT requests you will probably
need to set your workspace_client to some large value; typical
values range from 1MB to tens of megabytes depending on the max
size of your requests.

If you find any issues let us know! http://github.com/comotion/VSF/issues

Versions
========

Because we are closely tied to Varnish, VSF versions track Varnish versions. 

We have a four-numbered system like so:
VSF V.X.Y.Z
where::

  V is the major Varnish version, so for Varnish 4.x this is 4
  X is the minor Varnish version, so for Varnish 4.1 this is 1
  Y is the VSF major version, which changes when there are changes
    that require recompiling the VSF vmod.
  Z is the VSF minor release version, for minor changes and bugfixes.

We also have a 3.0-branch of VSF, which is code compatible with
Varnish 3.0. There are several new features in Varnish 4.1 that
make the current VSF possible, There will be no further developments
on the 3.0 branch.


Media
=====

* VSF at VUGX Rotterdam: http://www.delta9.pl/public/whyvsf2015/
* VSF on Init Tech Days 2014: https://www.youtube.com/watch?v=_zbk9_phkXg&feature=youtu.be
* VSF at Hack.lu 2012: http://archive.hack.lu/2012/VSF-hacklu2012.pdf

Future Work
===========

Write a handler to redirect triggered requests to a honeypot rather
than bugging out.
A handler could also do signature-based recognition of the
client/attacker.

See doc/ROADMAP for immediate plans.

Contributing
=============

Bugs and feature requests are welcome, and contributors are much obliged. 
Make us a pull request.


Credits
========

This work is based on the work of:

- VFW                           https://github.com/scarpellini/VFW
 - by Eduardo S. Scarpellini
- Security.VCL                  https://github.com/comotion/security.vcl
 - by Kristian Lyngstøl, Edward B. Fjellskål and Kacper Wysocki
- libvmod-vsf
 - by Federico G. Schwindt


As well as the authors of the following VMODs:

* Federico G. Schwindt:         https://github.com/fgsch/libvmod-utf8.git
* Syohei 'xcir' Tanaka:         https://github.com/xcir/libvmod-parsereq.git
* Dag Haavi Finstad:            https://github.com/varnish/libvmod-vsthrottle
* N. 'nand2' Deschildre:        https://github.com/nand2/libvmod-throttle.git
* Rogier 'DocWilco' Mulhuijzen: https://github.com/fastly/libvmod-urlcode.git
* Varnish Software ('martin'):  https://github.com/varnish/libvmod-shield.git

and the Varnish Cache by Poul-Henning Kamp, of course ;-)
