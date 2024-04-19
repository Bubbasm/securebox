import unittest
import json
import hashlib
import hmac
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from src.models import SymmetricKey, Container, Vault, GDrive
import src.config as config

config.SAVE_PATH = os.path.join('./', config.SAVE_FILE)


class TestSymmetricKey(unittest.TestCase):
    """Test the SymmetricKey class."""

    def setUp(self):
        self.key = SymmetricKey()

    def test_salt_and_iv(self):
        self.assertEqual(len(self.key.salt), 32)
        self.assertEqual(len(self.key.iv), 16)

    def test_generate_aes_key(self):
        aes_key1 = self.key.generate_aes_key("password")
        self.assertEqual(len(aes_key1), 32)
        aes_key2 = self.key.generate_aes_key("new_password")
        self.assertNotEqual(aes_key1, aes_key2)

    def test_get_key_json(self):
        key_json = self.key.get_key_json()
        self.assertIn(self.key.salt, base64.b64decode(key_json["salt"]))
        self.assertIn(self.key.iv, base64.b64decode(key_json["iv"]))


class TestContainer(unittest.TestCase):
    """Test the Container class."""

    def setUp(self):
        self.container = Container()
        self.test_id = 5
        self.test_name = "Test Container"
        self.test_data = "Test Data"
        self.password = "password"

    def test_id_counter(self):
        c1 = Container()
        c2 = Container()
        self.assertEqual(c2.get_id(), c1.get_id() + 1)

    def test_name(self):
        self.container.set_name(self.test_name)
        self.assertEqual(self.container.get_name(), self.test_name)

    def test_data(self):
        self.container.set_data(self.test_data)
        self.assertEqual(self.container.get_data(), self.test_data)

    def test_get_container_info(self):
        container_info = self.container.get_container_info()
        self.assertIn("id", container_info)
        self.assertIsInstance(container_info["id"], int)
        self.assertIn("name", container_info)
        self.assertIsInstance(container_info["name"], str)
        self.assertIn("data", container_info)
        self.assertIsInstance(container_info["data"], str)

    def test_from_data(self):
        # data for the container
        data = {
            "name": self.test_name,
            "data": self.test_data
        }
        plaintext = json.dumps(data).encode("utf-8")
        plaintext = pad(plaintext, AES.block_size)

        # encrypt the plaintext with aes256
        aes_key = self.container.key.generate_aes_key(self.password)
        cipher = AES.new(aes_key, AES.MODE_CBC, self.container.key.iv)
        ciphertext = cipher.encrypt(plaintext)
        mac = hmac.new(aes_key, str(self.test_id).encode(
            'utf-8') + ciphertext, hashlib.sha256).hexdigest()
        salt = self.container.key.salt
        iv = self.container.key.iv

        # create the container from the encrypted data and assert the values
        container = Container.from_data(
            self.password, str(self.test_id), ciphertext, mac, salt, iv)
        self.assertEqual(container.get_id(), self.test_id)
        self.assertEqual(container.get_name(), self.test_name)
        self.assertEqual(container.get_data(), self.test_data)

        with self.assertRaises(Container.LoadContainerError):
            Container.from_data(
                "invalid", str(self.test_id),
                ciphertext, mac, salt, iv)

        with self.assertRaises(Container.LoadContainerError):
            Container.from_data(
                self.password, str(self.test_id),
                ciphertext, "invalid", salt, iv)

        with self.assertRaises(ValueError):
            Container.from_data(
                self.password, str(self.test_id),
                ciphertext, mac, "invalid", iv)

        with self.assertRaises(ValueError):
            Container.from_data(
                self.password,
                str(self.test_id),
                ciphertext,
                mac,
                salt,
                "invalid")

    def test_encrypt(self):
        # data for the container
        self.container.set_name(self.test_name)
        self.container.set_data(self.test_data)

        # encrypt the container
        encrypted_data = self.container.encrypt(self.password)

        # manually encrypt the data to compare
        aes_key = self.container.key.generate_aes_key(self.password)
        cipher = AES.new(aes_key, AES.MODE_CBC, self.container.key.iv)
        plaintext = json.dumps({
            "name": self.container.get_name(),
            "data": self.container.get_data()
        }).encode("utf-8")
        containerid = f"{self.container.get_id()}".encode("utf-8")

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        mac = hmac.new(
            aes_key,
            containerid +
            ciphertext,
            hashlib.sha256).hexdigest()

        # assert the values
        self.assertEqual(
            base64.b64decode(
                encrypted_data["ciphertext"]),
            ciphertext)
        self.assertEqual(encrypted_data["mac"], mac)
        self.assertEqual(
            base64.b64decode(
                encrypted_data["key"]["salt"]),
            self.container.key.salt)
        self.assertEqual(
            base64.b64decode(
                encrypted_data["key"]["iv"]),
            self.container.key.iv)


class TestVault(unittest.TestCase):
    """Test the Vault class."""

    def setUp(self):
        self.master_pass = "master_password"
        self.vault = Vault(self.master_pass)
        self.test_id = 0
        self.test_name = "Test Container"
        self.test_data = "Test Data"
        self.password = "password"
        self.save_path = "vault_test.json"

    def test_add_remove_update_container(self):
        container = self.vault.add_container(
            self.test_name, self.test_data)
        self.assertEqual(container.get_name(), self.test_name)
        self.assertEqual(container.get_data(), self.test_data)

        self.vault.remove_container(container.get_id())
        self.assertEqual(self.vault.get_containers(), {})

        container = self.vault.add_container("", self.test_data)
        self.assertEqual(
            container.get_name(),
            "Container " + str(container.get_id()))
        self.assertEqual(container.get_data(), self.test_data)

        self.vault.update_container(
            container.get_id(),
            name=self.test_name, data="")
        self.assertEqual(container.get_name(), self.test_name)
        self.assertEqual(container.get_data(), "")
        self.vault.remove_container(container.get_id())

        with self.assertRaises(KeyError):
            self.vault.update_container(container.get_id(), name="", data="")

        with self.assertRaises(KeyError):
            self.vault.remove_container(container.get_id())

    def test_set_password(self):
        class SomeClass:
            def __init__(self):
                self.password = "password"
        self.vault.cloud = SomeClass()
        self.vault.set_master_password("new_password")
        self.assertEqual(self.vault.master_password, "new_password")
        self.assertEqual(self.vault.cloud.password, "new_password")

    def test_regenerate_keys(self):
        """
        Regenerate the key of the vault
        """
        old_key = self.vault.key
        self.vault.add_container(self.test_name, self.test_data)
        self.vault.regenerate_keys()
        self.assertNotEqual(old_key, self.vault.key)

    def test_get_container(self):
        container = self.vault.add_container(
            self.test_name, self.test_data)
        self.assertEqual(
            self.vault.get_container(
                container.get_id()),
            container)

        with self.assertRaises(KeyError):
            self.vault.get_container(-1)

    def test_encrypt(self):
        c1 = self.vault.add_container(self.test_name, self.test_data)
        c2 = self.vault.add_container(self.test_name, self.test_data)
        e1 = c1.encrypt(self.master_pass)
        e2 = c2.encrypt(self.master_pass)

        mac = hmac.new(
            self.vault.key.generate_aes_key(self.master_pass),
            (e1["mac"] + e2["mac"]).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        encrypted_vault = self.vault.encrypt()

        self.assertEqual(
            base64.b64decode(encrypted_vault["key"]["salt"]),
            self.vault.key.salt
        )
        self.assertEqual(
            base64.b64decode(encrypted_vault["key"]["iv"]),
            self.vault.key.iv
        )
        positive_id_containers = {
            c_id: e for c_id, e in
            encrypted_vault["containers"].items()
            if int(c_id) >= 0
        }
        self.assertEqual(
            positive_id_containers, {
                f"{c1.id}": e1, f"{c2.id}": e2})

    def test_fetch_container(self):
        container = self.vault.add_container(self.test_name, self.test_data)
        if os.path.exists(self.save_path):
            os.remove(self.save_path)

        with self.assertRaises(FileNotFoundError):
            Vault(self.master_pass, path=self.save_path)

        with open(self.save_path, "w") as f:
            f.write("invalid json")

        with self.assertRaises(Vault.LoadVaultError):
            Vault.fetch_container(
                str(container.get_id()),
                self.master_pass, self.save_path)

        self.vault.save_to_file(self.save_path)
        fetched_container = Vault.fetch_container(
            str(container.get_id()), self.master_pass, self.save_path)
        self.assertEqual(fetched_container.get_id(), container.get_id())
        self.assertEqual(fetched_container.get_name(), container.get_name())
        self.assertEqual(fetched_container.get_data(), container.get_data())

        with open(self.save_path, "w") as f:
            encrypted_vault = self.vault.encrypt()
            encrypted_vault.pop("containers")
            f.write(json.dumps(encrypted_vault))

        with self.assertRaises(Vault.LoadVaultError):
            Vault.fetch_container(
                str(container.get_id()),
                self.master_pass, self.save_path)

    def test_load_from_file(self):
        container = self.vault.add_container(self.test_name, self.test_data)

        if os.path.exists(self.save_path):
            os.remove(self.save_path)

        with self.assertRaises(FileNotFoundError):
            Vault(self.master_pass, path=self.save_path)

        with open(self.save_path, "w") as f:
            f.write("invalid json")

        with self.assertRaises(Vault.LoadVaultError):
            Vault(self.master_pass, path=self.save_path)

        with open(self.save_path, "w") as f:
            f.write(json.dumps(self.vault.encrypt()))

        new_vault = Vault(self.master_pass, path=self.save_path)
        self.assertEqual(
            new_vault.get_containers(),
            self.vault.get_containers())

        old_salt = self.vault.key.salt
        old_iv = self.vault.key.iv
        self.vault.key.salt = b"invalid"
        self.vault.key.iv = b"invalid"
        with open(self.save_path, "w") as f:
            f.write(json.dumps(self.vault.encrypt()))

        with self.assertRaises(Vault.LoadVaultError):
            Vault(self.master_pass, path=self.save_path)

        self.vault.key.salt = old_salt
        self.vault.key.iv = old_iv
        with open(self.save_path, "w") as f:
            encrypted_vault = self.vault.encrypt()
            encrypted_vault["mac"] = "invalid"
            f.write(json.dumps(encrypted_vault))

        with self.assertRaises(Vault.LoadVaultError):
            Vault(self.master_pass, path=self.save_path)

        with open(self.save_path, "w") as f:
            encrypted_vault = self.vault.encrypt()
            encrypted_vault.pop("mac")
            f.write(json.dumps(encrypted_vault))

        with self.assertRaises(Vault.LoadVaultError):
            Vault(self.master_pass, path=self.save_path)

        os.remove(self.save_path)

    def test_save_to_file(self):
        container = self.vault.add_container(self.test_name, self.test_data)
        if os.path.exists(self.save_path):
            os.remove(self.save_path)
        self.vault.save_to_file(self.save_path)
        self.assertTrue(os.path.exists(self.save_path))
        os.remove(self.save_path)

    def test_google_drive_backup(self):
        if os.path.exists(self.save_path):
            os.remove(self.save_path)
        credentials = None
        token = None
        if os.path.exists("credentials.json"):
            with open("credentials.json", "r") as f:
                credentials = f.read()
        if os.path.exists("token.json"):
            with open("token.json", "r") as f:
                token = f.read()
        self.vault.set_cloud_credentials(credentials, token)
        self.vault.save_to_file(self.save_path)
        self.vault.upload_backup("./" + self.save_path)
        self.vault.download_backup(f"./{self.save_path}.BAK")
        self.assertTrue(os.path.exists(f"{self.save_path}.BAK"))
        with open(self.save_path, "r") as f1, open(f"{self.save_path}.BAK", "r") as f2:
            self.assertEqual(f1.read(), f2.read())
        os.remove(self.save_path)
        os.remove(f"{self.save_path}.BAK")
        self.vault.cloud.delete_file(f"{self.save_path}.BAK")
        self.vault.cloud = None
        self.vault.set_cloud_credentials(
            json.dumps({"invalid": "invalid"}), "")
        try:
            self.vault.start_cloud()
        except Exception as e:
            pass
        self.vault.set_cloud_credentials("invalid", "")
        self.vault.upload_backup("./" + self.save_path)
        self.vault.set_cloud_credentials("", "")
        self.vault.download_backup(f"./{self.save_path}.BAK")


if __name__ == '__main__':
    unittest.main()
