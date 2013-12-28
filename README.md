Mediterraneancoin integration/staging tree
================================

http://www.mediterraneancoin.org

Copyright (c) 2009-2013 Bitcoin Developers<br/>
Copyright (c) 2009-2013 Litecoin Developers<br/>
Copyright (c) 2013-2014 Mediterraneancoin Developers<br/>

What is Mediterraneancoin?
----------------

Mediterraneancoin is a lite version of Bitcoin using an experimental new proof-of-work algorithm.

The new PoW algorithm is called "HybridScryptHash256".

It is described in detail here: http://www.mediterraneancoin.org/hybridscrypthash256.pdf

The idea is to allow all the users of erupters and similar small devices to mine an altcoin without having "whales" coming and disrupt mining.
With HybridScryptHash256, each HASH256 mining iteration with an erupter is encapsulated between two scrypt stages (whose parameters depend on the current difficulty).
In this way, a good amount of CPU power (or maybe even GPU power) is necessary for each HASH256 dedicated hardware.
If a miner owns a lot of HASH256 computing power, in order to mine Mediterraneancoins, he will need also a corresponding CPU power.
If the correspondent CPU power is not available, then the HASH256 compunting power is automatically limited.



 - 1 minute block targets
 - about 6 hour to retarget difficulty

Special reward system: random block rewards

blocks:<br/>
1-100k   : random 1-100 MediterraneanCoins reward<br/>
100k—200k: 1-200 MediterraneanCoins reward<br/>
200k—300k: 1-150 MediterraneanCoins reward<br/>
300k—400k: 1-100 MediterraneanCoins reward<br/>
400k—500k: 1-70 MediterraneanCoins reward<br/>
500k-600k: 1-40 MediterraneanCoins reward<br/>
&gt; 600k : 20 MediterraneanCoins reward (flat)<br/>
<br/>
after that, subsidy halves in 1036k blocks (~1 year)<br/>

 - 200 million total coins
 

For more information, as well as an immediately useable, binary version of
the Mediterraneancoin client sofware, see http://www.mediterraneancoin.org.

License
-------

Mediterraneancoin is released under the terms of the MIT license. See `COPYING` for more
information or see http://opensource.org/licenses/MIT.



