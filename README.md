# makepki

## Make X.509 PKI

Mass deploy X.509 public key infrastructure (PKI) for testing.

Depends on `openssl`, which should be available on your `PATH`.

Has a basic templating system to allow ranges and alternation for lists of hosts. As in:
    
    hosts:
        - node[01-99]
        - node-[x|y]

Run `makepki/make_pki.py <path to config>`

## Generate Diceware Passwords

Run `makepki/make_diceware_password.py <number of words>`

## TODO

  * Validate hostnames
  * Parallel key generation/signing