Version 1.3
===========

* Made command line parameters more persistent:
  -p -> -lp
  -l -> -lh
  -u -> -up
* Use a random password if neither '--auth' nor '--no-auth' are given.
* Generate a self-signed certificate if the user does not provide one. This
  way, SSL/TLS can be enabled by default.
