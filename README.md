# FastORE

This is an implementation of the order-revealing encryption (ORE) schemes
described in the following papers:
  * [Practical Order-Revealing Encryption with Limited Leakage](https://eprint.iacr.org/2015/1125.pdf) (ore.h)
  * [Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds](http://eprint.iacr.org/2016/612.pdf) (ore_blk.h)

This implementation is a research prototype mainly as a proof of concept, and is
not intended to be used in production-level code as it has not been carefully
analyzed for potential security flaws.

Authors:
 * David J. Wu, Stanford University
 * Kevin Lewi, Stanford University

Contact David for questions about the code:
  dwu4@cs.stanford.edu

## Prerequisites ##

Make sure you have the following installed:
 * [GMP 5.x](http://gmplib.org/)
 * [OpenSSL](http://www.openssl.org/source/)

## Installation ##

    git clone --recursive https://github.com/kevinlewi/fastore.git
    cd fastore
    make

## Running a Test ##

  ./tests/test_ore
