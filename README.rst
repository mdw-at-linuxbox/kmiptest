kmiptest
=========

kmip experiment code.

Links against <https://github.com/OpenKMIP/libkmip>.
Creates one symmetric key in kmip, using supplied parameters

Usage: ``kmip1`` [``-U`` `user`] [``-P`` `pw`] [``-C`` `cacert`]
[``-c`` `cert`] [``-k`` `key`] ``-p`` `portno` ``-h`` `host`

``-c`` `cert`
 Use this client certificate when making the ssl connection.

``-k`` key
 Use this client key when making the ssl connection.

``-U`` `user`
 Include a user and optional password credential in the request.

``-P`` `password`
 Specify the password for a username + password credential.

``-C`` `cert`
 Verify the server's certificate using this ca certificate.

``-p`` `port`
 Use this port number.  This parameter is required.

``-h`` `host`
 Connect to this host.  This parameter is required.

Sample command line::

 ./kmip1 -V -h kmip-server.example.com -p 5696 -U clientname \
 -c /tmp/client-certificate.pem -k /tmp/client-certificate.key
