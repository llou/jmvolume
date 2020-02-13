import os
import shutil
import unittest
from tempfile import mkdtemp
import jmvolume

LOCAL_PATH = os.path.dirname(os.path.abspath(__file__))


class UtilTestCase(unittest.TestCase):
    def test_execute(self):
        command1 = os.path.join(LOCAL_PATH, 'command.py')
        result = jmvolume.execute(command1, stdin="Milu")
        self.assertEqual(result, b"Milu")

        command2 = command1 + " 2"
        with self.assertRaises(jmvolume.CommandError) as e:
            result = jmvolume.execute(command2, stdin="Milu")
            self.assertEqual(e.returncode, 2)
            self.assertEqual(e.stdout, "Milu")
            self.assertEqual(e.stderr, "Milu")

    def test_random_string(self):
        string = jmvolume.random_string(length=40)
        self.assertEqual(len(string), 40)


class CryptVolumeTestCase1(unittest.TestCase):
    volume_name = 'localin'
    device_name = "jmvolume_test"
    device_path = os.path.join("/dev/mapper", device_name)

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="jmvolume-test-")
        self.volume_path = os.path.join(self.temp_dir, self.volume_name)
        self.key = jmvolume.random_string(length=400)

    def test_build(self):
        cv = jmvolume.CryptVolume.build(self.volume_path,
                                        self.key,
                                        device_name=self.device_name)
        self.assertTrue(os.path.exists(self.volume_path))
        cv.delete()
        self.assertFalse(os.path.exists(self.volume_path))

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


class CryptVolumeTestCase2(unittest.TestCase):
    volume_name = 'localin'
    device_name = "jmvolume_test"
    device_path = os.path.join("/dev/mapper", device_name)

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="jmvolume-test-")
        self.volume_path = os.path.join(self.temp_dir, self.volume_name)
        self.key1 = jmvolume.random_string(length=400)
        self.key2 = jmvolume.random_string(length=400)
        self.cv = jmvolume.CryptVolume.build(self.volume_path,
                                             self.key1,
                                             device_name=self.device_name)

    def test_decrypt_encrypt(self):
        self.cv.decrypt(self.key1)
        self.assertTrue(os.path.exists(self.device_path))
        self.assertTrue(self.cv.is_decrypted)
        self.cv.encrypt()
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
        with self.assertRaises(jmvolume.CommandError):
            self.cv.decrypt(self.key2, slot=1)

    def tearDown(self):
        if self.cv.is_decrypted:
            self.cv.encrypt()
        self.cv.delete()
        shutil.rmtree(self.temp_dir)


class KeyTestCase(unittest.TestCase):
    key_name = "jmvolume.jmvolume.key"
    passphrase = "jmvolume"
    cls = jmvolume.Key
    length = 1024

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="jmvolume-test-")
        self.key_path = os.path.join(self.temp_dir, self.key_name)

    def assert_ascii(self, text):
        for c in text:
            self.assertIn(c, jmvolume.symbols)

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
    mapper_name = "jmvolume-test"

    def setUp(self):
        self.temp_dir = mkdtemp(prefix="jmvolume-test-")
        self.key = jmvolume.random_string(length=1024)
        self.volume_path = os.path.join(self.temp_dir, "volume")
        self.mount_point = os.path.join(self.temp_dir, "jmvolume")
        self.cv = jmvolume.CryptVolume.build(self.volume_path, self.key)
        jmvolume.execute('mkdir -p %s' % self.mount_point)

    def test_mount(self):
        self.volume = jmvolume.Volume(self.volume_path, self.mount_point,
                                      self.mapper_name)
        self.volume.mount(self.key)
        self.assertTrue(self.volume.is_mounted)
        self.volume.umount()
        self.assertFalse(self.volume.is_mounted)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


if __name__ == '__main__':
    if os.path.exists('/dev/mapper/jmvolume_test'):
        jmvolume.execute('cryptsetup luksClose /dev/mapper/jmvolume_test')
    unittest.main()
