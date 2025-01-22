Install [SoftHSMv2](https://github.com/softhsm/SoftHSMv2)

This example uses [rust-cryptoki](https://github.com/parallaxsecond/rust-cryptoki)

Clone the repo. To run the test:
```shell
mkdir /tmp/tokens
echo "directories.tokendir = /tmp/tokens" > /tmp/softhsm2.conf
export PKCS11_SOFTHSM2_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export SOFTHSM2_CONF="/tmp/softhsm2.conf"
```
Set `PKCS11_SOFTHSM2_MODULE` according to the location of the softhsm pkcs11 library.

Then run: `cargo run`

