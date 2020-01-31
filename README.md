# The localo project

These are a set of tools for managing encrypted volumes using the standard linux
commands. It consist in two wrappers of the most used cryptographic utilities
that are *GnuPG* and *cryptsetup*, and this projects use them together to symplify
the development of Python solutions that are reliable and easy to maintain.

## The Cryptvolume class

This class gives the programmer a wrapper around *cryptsetup* and implements the
most frequent use cases in the management of this kind of encrypted volumes.

It comes with a constructor that wraps the building of a volume avoiding the
sometimes intrincate path of the process.

Once instantiated it can be decrypted as a new device and the way back, and
it also provides methods to insert, remove, and change keys of the volume.

## The Volume class

This class wraps up the previous one and assists in the construction of a mounted
volume that provides access to the data stored in the encrypted one.

## The Key class

No cryptographic volume is safe without the provisioning of large randomly generated
cryptographic keys. This class provides two kind of keys one symetrically encrypted 
with *GnuPG* and the other one without encryption.

The encrypted keys are intended to be used in production and the raw ones used as
backup to be stored safely.

