# Monero signature verification example - pure Python

While there are lots of sites describing Monero's ring signatures at a high level, I had a hard time finding any that had actual code examples,
down to the gritty details. The closest thing is the main client code, which is a bit unclear and sometimes hard to follow.

This code is pure Python and hopefully easier to follow - it shows how the signature in
[the first non-Coinbase transaction of Monero](https://xmrchain.net/search?value=beb76a82ea17400cd6d7f595f70e1667d2018ed8f5a78d1ce07484222618c3cd)
is verified. Note that is is a version 1 transaction, before RingCT, before Bulletproof, just a pure ring signature.

The [Cryptonote 2.0 whitepaper](https://cryptonote.org/whitepaper.pdf) explains most of the details that goes into ring signature verification,
but there are a few vital details missing. First, the function **H**<sub>p</sub> which takes an elliptic curve point, hashes it, and generates
another elliptic curve point, is not defined. It turnes out that this function is implemented as
[ge_fromfe_frombytes_vartime](https://github.com/monero-project/monero/blob/master/src/crypto/crypto-ops.c#L2310) in the reference client, and
isn't really documented. Thankfully, there also exists a Python implementation in the Mininero project, as the function
[hashToPointCN](https://github.com/monero-project/mininero/blob/master/mininero.py#L238).

Secondly, the definition of the final signature hash differs between the paper and the client - while the paper describes it as
H(m, L<sub>0</sub>, L<sub>1</sub>, ..., R<sub>0</sub>, R<sub>1</sub>, ...) it's actually implemented in the code as
H(m, L<sub>0</sub>, R<sub>0</sub>, L<sub>1</sub>, R<sub>1</sub>, ...) - it's unclear why this was changed, as the cryptographic strength should be
the same.