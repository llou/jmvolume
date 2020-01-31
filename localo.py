from __future__ import print_function
"""
======
Localo
======

This is a linux command developed with the intention of simplifying the
integration between the system encrypted volume manager LUKS for handling
encrypted volumes and GnuPG to provide an easy way to handle large volume keys
with easy memorizable passwords.

This command should provide with all the functions that simplify volume keys
management.

It also provides with the tools to use backup unencrypted keys as an
exceptional way to unlock the volume contents.

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

symbols = string.letters + string.digits


# Utility functions

def random_string(length=20):
    return "".join(random.choice(symbols) for i in range(length))


def execute(command, stdin=""):
    p = Popen(command, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)
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
    This class represents the luks volume and an interface with it.
    """

    @classmethod
    def create(cls, path, key, size_m=40, rewrite=False, backup_key=None,
               backup_key_slot=3, device_name=random_string()):
        """
        This classmethod will create a new cryptvolume given the parameters
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
        self.volume_path = volume_path
        self.mapper_name = mapper_name
        self.mapper_device = os.path.join("/dev/mapper", self.mapper_name)

    @property
    def is_decrypted(self):
        return os.path.exists(self.mapper_device)

    def decrypt(self, key, slot=0):
        v = (slot, self.volume_path, self.mapper_name)
        execute("cryptsetup -d - --key-slot %d luksOpen %s %s" % v, stdin=key)

    def destroy(self):
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
            self.destroy()
        os.remove(self.volume_path)


class Key(object):
    """
    This class abstracts the key file object.
    """

    @classmethod
    def build(cls, path, passphrase, length=1024, rewrite=False):
        if os.path.exists(path) and not rewrite:
            raise VolumeError("Key already exists")
        raw_key = cls.generate_key(length)
        result = gpg.encrypt(raw_key, [], symmetric=ALGORITHM,
                             passphrase=passphrase)
        with file(path, "wb") as f:
            f.write(result.data)
        return cls(path)

    @classmethod
    def build_raw(cls, path, length=1024, rewrite=False):
        if os.path.exists(path) and not rewrite:
            raise VolumeError("Key already exists")
        raw_key = cls.generate_key(length)
        with file(path, "wb") as f:
            f.write(raw_key)
        return cls(path)

    @classmethod
    def generate_key(cls, length=1024):
        return random_string(length=length)

    def __init__(self, path, raw=False):
        self.path = path
        self.raw = raw

    def decrypt(self, passphrase):
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
    This class abstracts the part of the operating system mounting and
    unmounting the volume
    """

    def __init__(self, volume_path, mount_point, mapper_name):
        self.volume_path = volume_path
        self.mount_point = mount_point
        self.mapper_name = mapper_name
        self.crypto_volume = CryptVolume(volume_path, self.mapper_name)
        self.mapper_volume = self.crypto_volume.mapper_device

    def mount(self, key):
        if self.is_mounted:
            logging.error("Already mounted")
        if self.crypto_volume.is_decrypted:
            logging.info("Already decrypted")
        else:
            self.crypto_volume.decrypt(key)
        execute("mount %s %s" % (self.mapper_volume, self.mount_point))

    def umount(self):
        if self.is_mounted:
            try:
                execute("umount %s" % self.mapper_volume)
            except CommandError:
                open_files = execute("lsof %s" % self.mount_point)
                print("Unable to umount: Open files:")
                print(open_files)
                return
        if self.crypto_volume.is_decrypted:
            self.crypto_volume.destroy()

    @property
    def is_mounted(self):
        mounts = execute("mount")
        regex = re.compile("%s on %s" % (self.mapper_volume, self.mount_point))
        return bool(regex.search(mounts))
