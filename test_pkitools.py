# Quick and dirty tests for developing pkitools.
# TODO: turn this into actual unit tests
import pkitools

test1 = 'abc[01-03]def[9-11]ghi[x|yy]'
test2 = 'node[01-20]'

exp1 = pkitools.expand(test1)
exp2 = pkitools.expand(test2)

print(exp1)
print(exp2)

