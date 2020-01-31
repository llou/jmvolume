import sys
import os
import shutil
import unittest
from tempfile import mkdtemp
sys.path.insert(0, "..")
import localo

LOCAL_PATH = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.join(LOCAL_PATH, 'fixtures')


class UtilTestCase(unittest.TestCase):
    def test_execute(self):
        command1 = os.path.join(FIXTURES_DIR, 'command.py')
        result = localo.execute(command1, stdin="Milu")
        self.assertEqual(result, b"Milu")

        command2 = command1 + " 2"
        with self.assertRaises(localo.CommandError) as e:
            result = localo.execute(command2, stdin="Milu")
            self.assertEqual(e.returncode, 2)
            self.assertEqual(e.stdout, "Milu")
            self.assertEqual(e.stderr, "Milu")

    def test_random_string(self):
        string = localo.random_string(length=40)
        self.assertEqual(len(string), 40)


class CryptVolumeTestCase1(unittest.TestCase):
    volume_name = 'localin'
    device_name = "localo_test"
    device_path = os.path.join("/dev/mapper", device_name)

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="localo-test-")
        self.volume_path = os.path.join(self.temp_dir, self.volume_name)
        self.key = localo.random_string(length=400)

    def test_create_delete(self):
        cv = localo.CryptVolume.create(self.volume_path,
                                       self.key,
                                       device_name=self.device_name)
        self.assertTrue(os.path.exists(self.volume_path))
        cv.delete()
        self.assertFalse(os.path.exists(self.volume_path))

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


class CryptVolumeTestCase2(unittest.TestCase):
    volume_name = 'localin'
    device_name = "localo_test"
    device_path = os.path.join("/dev/mapper", device_name)

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="localo-test-")
        self.volume_path = os.path.join(self.temp_dir, self.volume_name)
        self.key1 = localo.random_string(length=400)
        self.key2 = localo.random_string(length=400)
        self.cv = localo.CryptVolume.create(self.volume_path,
                                            self.key1,
                                            device_name=self.device_name)

    def test_decrypt_destroy(self):
        self.cv.decrypt(self.key1)
        self.assertTrue(os.path.exists(self.device_path))
        self.assertTrue(self.cv.is_decrypted)
        self.cv.destroy()
        self.assertFalse(self.cv.is_decrypted)
        self.assertFalse(os.path.exists(self.device_path))

    def test_add_new_key(self):
        self.cv.add_new_key(self.key1, self.key2, slot=1)
        self.cv.decrypt(self.key2, slot=1)
        self.assertTrue(self.cv.is_decrypted)

    def test_change_key(self):
        self.cv.change_key(self.key1, self.key2, slot=0)
        self.cv.decrypt(self.key2, slot=0)
        self.assertTrue(self.cv.is_decrypted)

    def test_remove_key(self):
        self.cv.add_new_key(self.key1, self.key2, slot=1)
        self.cv.remove_key(self.key1, slot=1)
        with self.assertRaises(localo.CommandError):
            self.cv.decrypt(self.key2, slot=1)

    def tearDown(self):
        if self.cv.is_decrypted:
            self.cv.destroy()
        self.cv.delete()
        shutil.rmtree(self.temp_dir)


class KeyTestCase(unittest.TestCase):
    key_name = "localo.localo.key"
    passphrase = "localo"
    cls = localo.Key
    length = 1024

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="localo-test-")
        self.key_path = os.path.join(self.temp_dir, self.key_name)

    def assert_ascii(self, text):
        for c in text:
            self.assertIn(c, localo.symbols)

    def test_generate_key(self):
        raw_key = self.cls.generate_key(length=self.length)
        self.assertEqual(len(raw_key), self.length)
        self.assert_ascii(raw_key)

    def test_build(self):
        key_object = self.cls.build(self.key_path, self.passphrase,
                                    length=self.length)
        raw_key = key_object.decrypt(self.passphrase)
        self.assertEqual(len(raw_key), self.length)
        self.assert_ascii(raw_key.decode('ascii'))

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


class VolumeTestCase(unittest.TestCase):
    volume_path = os.path.join(FIXTURES_DIR, "volume.enc")
    key_path = os.path.join(FIXTURES_DIR, "key.raw")
    mount_point = "/tmp/localo-test"
    flag = os.path.join(mount_point, "localo")
    mapper_name = "localo-test"

    def setUp(self):
        localo.execute('mkdir -p %s' % self.mount_point)
        self.volume = localo.Volume(self.volume_path, self.mount_point,
                                    self.mapper_name)
        with open(self.key_path) as f:
            self.key = f.read()

    def test_mount(self):
        self.volume.mount(self.key)
        self.assertTrue(os.path.exists(self.flag))
        self.assertTrue(self.volume.is_mounted)
        self.volume.umount()
        self.assertFalse(self.volume.is_mounted)


if __name__ == '__main__':
    unittest.main()
