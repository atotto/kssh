# SSH client with Google Cloud KMS

    $ go get github.com/atotto/kssh

You can set Google Cloud KMS resource ID:

    $ export KSSH_KEY_PATH=projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION]

Supported Cloud KMS algorithm:

- EC_SIGN_P256_SHA256


## authorized_key

Print public key:

    $ kssh --authorized_key
    ecdsa-sha2-nistp256 AAAAzzz

You can copy the public key to ~/.ssh/authorized_keys in your home directory on the remote machine.

## ssh login

    $ kssh username@hostname

## usage

    $ kssh --help
