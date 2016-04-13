# makepki

Mass deploy X.509 public key infrastructure (PKI) for testing.

Depends on `openssl`, which should be available on your `PATH`.

TODO: Basic templating system to allow ranges and alternation for lists of hosts. As in:
    
    hosts:
        - node[01-99]