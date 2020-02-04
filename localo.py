from __future__ import print_function
"""
==================
The localo project
==================

This is a Python module that wraps standard Linux cryptografic tools to create
and manage encrypted volumes and their keys. Using cryptsetup can be a tedious
job as the commands are intrincate and you have to do it with a lot of care of
doing it the right way because one mistake can result in the loss o secrecy, or
worst, with the irrevocable loss of information.

This code is supoused to be run with root privileges and to manage sensitive
data, this is why I tried to keep it as symple as posible, so any experienced
admin can check what it does in a few minutes.

This project is in its alpha stage so use it with care.

"""
import os
import re
import logging
import random
import string
import gnupg
from subprocess import Popen, PIPE

ALGORITHM = "AES256"

gpg = gnupg.GPG()

symbols = string.ascii_letters + string.digits


# Utility functions

def random_string(length=20):
    return "".join(random.choice(symbols) for i in range(length))


def execute(command, stdin=""):
    p = Popen(command, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)
    if hasattr(stdin, "encode"):
        stdin = stdin.encode("ascii")
    stdout, stderr = p.communicate(stdin)
    if p.returncode:
        raise CommandError(command, p.returncode, stdout, stderr)
    return stdout


# Exceptions

class LocaloError(Exception):
    pass


class VolumeError(LocaloError):
    pass


class KeyError(LocaloError):
    pass


class CommandError(LocaloError):
    def __init__(self, command, returncode, stdout, stderr):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        error = "Error %d running: '%s'" % (self.returncode, self.command)
        if self.stdout:
            error += "\nreturned output:\n%s" % self.stdout
        if self.stderr:
            error += "\nreturned error:\n%s" % self.stderr
        return error


# Classes

class CryptVolume(object):
    """
    This class is the wrapper around *cryptsetup* and in its methods implements
    frequent use cases in the management of this kind of encrypted volumes.
    """

    @classmethod
    def build(cls, path, key, size_m=40, rewrite=False, backup_key=None,
               backup_key_slot=3, device_name=random_string()):
        """
        This constructor builds an empty encrypted volume given the parameters:

            path: str
                The place in the filesystem for the volume
            key: str
                An ascii string used to lock the volume
            size(MB): int
                The size of the volume
            overwrite: bool
                If it will overwrite an existing file
            backup_key: str
                an ascii string that unlocks the device in case of
                losing the main one
            backup_key_slot: int
                the volume slot in where to put the backup_key
                device_name: the name of mapper device used while formatting the
                volume
        """

        if os.path.exists(path) and not rewrite:
            raise VolumeError("Encrypted volume already exists")
        blocks = size_m * 1024
        execute("dd if=/dev/zero of=%s bs=1024 count=%d" % (path, blocks))
        execute("cryptsetup -d - luksFormat %s" % path, stdin=key)
        execute("cryptsetup -d - luksOpen %s %s" % (path, device_name),
                stdin=key)
        execute("mkfs.ext3 /dev/mapper/%s" % device_name)
        execute("cryptsetup luksClose %s" % device_name)
        cv = cls(path, device_name)
        if backup_key is not None:
            cv.add_new_key(key, backup_key, slot=backup_key_slot)
        return cv

    def __init__(self, volume_path, mapper_name):
        """
        This class represents an encrypted volume and is instantiated with two
        parameters:
            volume_path: str
                The place in the filesystem of the volume
            mapper_name: str
                The name of the mapper device used when decrypting the volume
        """
        self.volume_path = volume_path
        self.mapper_name = mapper_name
        self.mapper_device = os.path.join("/dev/mapper", self.mapper_name)

    @property
    def is_decrypted(self):
        "Checks if the device is ready to be mounted"

        return os.path.exists(self.mapper_device)

    def decrypt(self, key, slot=0):
        """
        Given the key it creates the decrypted device to access volume content
            key: str
                The ascii text that unlocks the contents
            slot: int
                The slot it is expected to fit the key
        """

        v = (slot, self.volume_path, self.mapper_name)
        execute("cryptsetup -d - --key-slot %d luksOpen %s %s" % v, stdin=key)

    def encrypt(self):
        "Once unmounted volume it shuts down the device."

        execute("cryptsetup luksClose %s" % self.mapper_name)

    def add_new_key(self, key, newkey, slot=1):
        """
        Adds a new key given a current one. As it mixes them they should be
        ascii to work without problems.
        """
        mix = "%s%s" % (key, newkey)
        length = len(key)
        execute("cryptsetup -d - --keyfile-size %d --key-slot %d luksAddKey %s"% (length, slot, self.volume_path), stdin=mix)

    def change_key(self, key, newkey, slot=0):
        """
        Changes an existing key given a current one. As it mixes them the
        should be ascii to work without problems.
        """
        mix = "%s%s" % (key, newkey)
        length = len(key)
        execute("cryptsetup -d - --keyfile-size %d --key-slot %d luksChangeKey %s" % (length, slot, self.volume_path), stdin=mix)

    def remove_key(self, key, slot):
        if slot == 0:
            raise VolumeError("Cannot wipe slot 0")
        execute("cryptsetup -d - luksKillSlot %s %d" % (self.volume_path,
                                                        slot), stdin=key)

    def delete(self):
        if self.is_decrypted:
            self.encrypt()
        os.remove(self.volume_path)


class Key(object):
    """
    No cryptographic volume is safe without the provisioning of large randomly
    generated cryptographic keys. This class provides two kind of keys one
    symetrically encrypted with *GnuPG* and the other one without encryption.

    The encrypted keys are intended to be used in production and the raw ones
    used as backup to be stored safely.
    """

    @classmethod
    def build(cls, path, passphrase, length=1024, rewrite=False):
        """
        This constructor creates a symmetrically encrypted, this means the key
        is protected by a password, file by GnuPG already formated to be easily
        manipulated by the cryptsetup system like updating and adding new keys
        to the volume.

            path: str
                The location in the file system of the created key
            passphrase: str
                The string that unlocks the key via GnuPG
            length: int
                The length of the randomly created string
            overwrite: bool
                If the key will replace another file in the given path
        """

        if os.path.exists(path) and not rewrite:
            raise VolumeError("Key already exists")
        raw_key = cls.generate_key(length)
        result = gpg.encrypt(raw_key, [], symmetric=ALGORITHM,
                             passphrase=passphrase)
        with open(path, "wb") as f:
            f.write(result.data)
        return cls(path)

    @classmethod
    def build_raw(cls, path, length=1024, rewrite=False):
        """
        Some times is there the need to keep a key safe in the vault just in
        case the other keys or passwords are lost, this constructor build
        a plain key just in case.

            path: str
                The location in the file system of the created key
            passphrase: str
                The string that unlocks the key via GnuPG
            length: int
                The length of the randomly created string
            overwrite: bool
                If the key will replace another file in the given path
        """

        if os.path.exists(path) and not rewrite:
            raise VolumeError("Key already exists")
        raw_key = cls.generate_key(length)
        with file(path, "wb") as f:
            f.write(raw_key)
        return cls(path)

    @staticmethod
    def generate_key(length=1024):
        """
        This method randombly assembles an ascii string of the given length

            length: int
                The length of the string
        """

        return random_string(length=length)

    def __init__(self, path, raw=False):
        self.path = path
        self.raw = raw

    def decrypt(self, passphrase):
        """
        This method unencrypts the contents of the Key object ready to be
        used in unlocking a volume

            passphrase: str
                The password that decrypts the key.
        """

        try:
            with open(self.path, "rb") as f:
                key = gpg.decrypt_file(f, passphrase=passphrase)
        except IOError:
            raise VolumeError("Error reading key file")
        if not key.ok:
            # raise VolumeError("Error decrypting key file")
            pass
        return key.data


class Volume(object):
    """
    This class wraps up the cryptographic volume class and does the part of
    interfacing between it and the os filesystem tools.
    """

    def __init__(self, volume_path, mount_point, mapper_name):
        """
        To intialize this class you require of three arguments:
            volume_path: str
                where is the encrypted volume stored
            mount_point: str
                what is the path to the place the cryptographic volume is to
                be mounted
            mapper_name: str
                the name of the intermediary device that is used to interact
                between the cryptographic subsystem and the os filesystem
                tools.
        """

        self.volume_path = volume_path
        self.mount_point = mount_point
        self.mapper_name = mapper_name
        self.crypto_volume = CryptVolume(volume_path, self.mapper_name)
        self.mapper_volume = self.crypto_volume.mapper_device

    def mount(self, key):
        """
        Given an unencrypted key it mounts the volume as defined

            key: str
                unencrypted key to unlock the volume
        """

        if self.is_mounted:
            logging.error("Already mounted")
        if self.crypto_volume.is_decrypted:
            logging.info("Already decrypted")
        else:
            self.crypto_volume.decrypt(key)
        execute("mount %s %s" % (self.mapper_volume, self.mount_point))

    def umount(self):
        """
        It unmounts and "encrypts" back the volume, doing a few tests to do it
        safely.
        """

        if self.is_mounted:
            try:
                execute("umount %s" % self.mapper_volume)
            except CommandError:
                open_files = execute("lsof %s" % self.mount_point)
                print("Unable to umount: Open files:")
                print(open_files)
                return
        if self.crypto_volume.is_decrypted:
            self.crypto_volume.encrypt()

    @property
    def is_mounted(self):
        """
        Checks if the volume is mounted by checking the mounted devices list
        """

        mounts = execute("mount")
        regex = re.compile("%s on %s" % (self.mapper_volume, self.mount_point))
        return bool(regex.search(mounts.decode("ascii")))
