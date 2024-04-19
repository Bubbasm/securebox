"""
File: models.py
Author: Bhavuk Sikka and Samuel de Lucas
Date: 21-02-2024

Description: This file contains the models for the application
"""

import hashlib
import json
import hmac
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import os
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload


class SymmetricKey:
    """
    Class representing a symmetric AES key
    """

    KEY_SIZE = 32   # AES.key_size[-1]
    SALT_SIZE = 32
    BLOCK_SIZE = 16
    PBKDF2_ALGORITHM = "sha256"
    PBKDF2_ITERATIONS = 500000

    def __init__(self, salt: bytes = None, iv: bytes = None):
        self.salt: bytes = salt if salt else Random.new().read(self.SALT_SIZE)
        self.iv: bytes = iv if iv else Random.new().read(self.BLOCK_SIZE)
        self.aeskey: bytes = None
        self.prev_password: str = None

    def generate_aes_key(self, password: str) -> bytes:
        """
        Generate an AES key from a password

        :param str password: password to generate the key from
        :return: AES key
        """
        if self.aeskey is not None and self.prev_password == password:
            return self.aeskey
        self.aeskey = hashlib.pbkdf2_hmac(
            self.PBKDF2_ALGORITHM,
            password.encode('utf-8'),
            self.salt,
            self.PBKDF2_ITERATIONS,
            self.KEY_SIZE
        )
        self.prev_password = password
        return self.aeskey

    def get_key_json(self) -> dict:
        """
        Get the information of the key

        :return: dict containing the information of the key
        """
        return {
            "salt": base64.b64encode(self.salt).decode('utf-8'),
            "iv": base64.b64encode(self.iv).decode('utf-8')
        }


class Container:
    """
    Class representing a container
    """
    next_id: int = 0

    class LoadContainerError(Exception):
        """Exception raised when the container could not be loaded from data"""

    def __init__(self, id: int = None):
        if id is not None:
            self.id = id
        else:
            self.id: int = Container.next_id
        Container.next_id = max(Container.next_id, self.id + 1)
        self.name: str = ""
        self.key: SymmetricKey = SymmetricKey()
        self.data: bytes = b""

    def get_id(self) -> int:
        """
        Get the id of the container

        :return: id of the container
        """
        return self.id

    def get_name(self) -> str:
        """
        Get the name of the container

        :return: name of the container
        """
        return self.name

    def get_data(self) -> str:
        """
        Get the data of the container

        :return: data of the container
        """
        return self.data.decode('utf-8')

    def get_container_info(self) -> dict:
        """
        Get the information of the container

        :return: dict containing the information of the container
        """
        return {
            "id": self.get_id(),
            "name": self.get_name(),
            "data": self.get_data()
        }

    def set_name(self, name: str):
        """
        Set the name of the container

        :param str name: name of the container
        """
        self.name = name

    def set_data(self, data: str):
        """
        Set the data of the container

        :param str data: data of the container
        """
        self.data = data.encode('utf-8')

    @staticmethod
    def from_data(
            password: str,
            id: str,
            ciphertext: bytes,
            mac: bytes,
            salt: bytes,
            iv: bytes) -> "Container":
        """
        Load container from given data (mainly used for loading from file).
        Decrypts the data and returns the corresponding container.

        :param str password: password to decrypt the data
        :param str id: id of the container
        :param bytes ciphertext: encrypted data
        :param bytes mac: given mac, used to check
                          the integrity of the container
        :param bytes salt: salt used to generate the key
        :param bytes iv: initialization vector
        :return: container
        :raise ValueError: if the mac is invalid or the container is corrupted
        :raise LoadContainerError: if the container could not be loaded from data
        """
        if len(salt) != SymmetricKey.SALT_SIZE or \
                len(iv) != SymmetricKey.BLOCK_SIZE:
            raise ValueError("Invalid data")

        container = Container(int(id))
        loaded_key = SymmetricKey(salt, iv)
        aes_key = loaded_key.generate_aes_key(password)
        computed_mac = hmac.new(
            aes_key,
            id.encode('utf-8') + ciphertext, hashlib.sha256).hexdigest()

        # Check container integrity
        # We just check the MAC instead of decrypting the data
        # (and rejecting it because of incorrect padding)
        # to avoid potential padding oracle attacks
        if not hmac.compare_digest(computed_mac, mac):
            msg = f"Integrity Error: Invalid container MAC for container {id}.\nThe container may have been tampered with."
            raise Container.LoadContainerError(msg)

        # Decrypt the data
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        jsonPlaintext = json.loads(plaintext.decode('utf-8'))
        container.set_name(jsonPlaintext["name"])
        container.set_data(jsonPlaintext["data"])
        container.key = loaded_key

        return container

    def encrypt(self, password: str) -> dict:
        """
        Encrypt the container and return the data so that
        it can be saved to a file

        :return: dictionary containing the encrypted data, mac, salt and iv
        """
        plaintext = json.dumps({
            "name": self.name,
            "data": self.data.decode('utf-8')
        }).encode('utf-8')
        plaintext = pad(plaintext, AES.block_size)
        aes_key = self.key.generate_aes_key(password)
        cipher = AES.new(aes_key, AES.MODE_CBC, self.key.iv)
        ciphertext = cipher.encrypt(plaintext)
        # include the id in the mac message for integrity
        mac_message = str(self.id).encode('utf-8') + ciphertext
        computed_mac = hmac.new(
            aes_key,
            mac_message, hashlib.sha256).hexdigest()

        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "mac": computed_mac,
            "key": self.key.get_key_json()
        }

    def __eq__(self, other: "Container") -> bool:
        """
        Compare two containers

        :param Container other: container to compare with
        :return: True if the containers are equal, False otherwise
        """
        return self.id == other.id and \
            self.name == other.name and \
            self.data == other.data


class Vault:
    """
    Class representing a vault
    """
    class LoadVaultError(Exception):
        """Exception raised when the vault could not be loaded"""

    def __init__(self, master_password: str, path: str = None):
        """
        Constructor of the Vault class

        :param str master_password: master password of the vault
        :param str path: path to json file
        :raise LoadVaultError: if path was given and the file
                               could not be loaded into the vault
        """
        self.key: SymmetricKey = SymmetricKey()
        self.containers: dict[int, Container] = {}
        self.master_password: str = master_password
        self.cloud = None
        self.hidden_containers = {-1: Container(-1), -2: Container(-2)}
        self.hidden_containers[-1].set_name("Credential")
        self.hidden_containers[-2].set_name("Token")

        if path is not None:
            self.load_from_file(path)

    def add_container(self, name: str, data: str) -> Container:
        """
        Add a container to the vault

        :param str name: name of the container
        :param str data: data of the container
        """
        container = Container()
        if name == "":
            name = f"Container {container.get_id()}"
        container.set_name(name)
        container.set_data(data)
        self.containers[container.get_id()] = container
        return container

    def remove_container(self, id: int):
        """
        Remove a container from the vault

        :param int id: id of the container to remove
        :raise KeyError: if the container was not found
        """
        try:
            self.containers.pop(id)
        except KeyError:
            raise KeyError(
                f"Could not delete: Container with ID {id} not found")

    def update_container(self, id: int, name: str = None, data: str = None):
        """
        Update a container in the vault

        :param int id: id of the container to update
        :param str name: new name of the container
        :param str data: new data of the container
        :raise KeyError: if the container was not found
        """
        try:
            all_containers = self.containers | self.hidden_containers
            container = all_containers[id]
            if name is not None:
                container.set_name(name)
            if data is not None:
                container.set_data(data)
        except KeyError:
            raise KeyError(
                f"Could not update: Container with ID {id} not found")

    def get_container(self, id: int) -> Container:
        """
        Get a container from the vault

        :param int id: id of the container to get
        :return: container
        :raise KeyError: if the container was not found
        """
        try:
            return self.containers[id]
        except KeyError:
            raise KeyError(f"Container with ID {id} not found")

    def get_containers(self) -> list[Container]:
        """
        Get all the containers from the vault

        :return: list of containers
        """
        return self.containers

    def encrypt(self) -> dict:
        """
        Encrypt the vault and return the data so that it can be saved to a file

        :return: dictionary containing the encrypted data, mac and key
        """
        all_containers = self.containers | self.hidden_containers
        enc_containers = {
            f"{c_id}": c.encrypt(self.master_password)
            for c_id, c in all_containers.items()
        }
        container_macs = [c["mac"]
                          for c_id, c in sorted(enc_containers.items())]
        mac = hmac.new(
            self.key.generate_aes_key(self.master_password),
            "".join(container_macs).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return {
            "containers": enc_containers,
            "key": self.key.get_key_json(),
            "mac": mac
        }

    @staticmethod
    def fetch_container(id: str, password: str, path: str) -> Container:
        """
        Fetch a container from the vault

        :param str id: id of the container to fetch
        :param str password: master password of the vault
        :param str path: path to json file
        :return: container
        :raise LoadContainerError: if the container could not be loaded from data
        :raise LoadVaultError: if there was any other error fetching the container
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            msg = "Could not load vault: Invalid JSON (file may be corrupted/empty)"
            raise Vault.LoadVaultError(msg)

        try:
            c = data["containers"][id]
            container = Container.from_data(
                password,
                id,
                base64.b64decode(c["ciphertext"]),
                c["mac"],
                base64.b64decode(c["key"]["salt"]),
                base64.b64decode(c["key"]["iv"])
            )
            return container
        # except Container.LoadContainerError as e: # not needed
        #     raise e
        except Exception as e:
            msg = f"There was an error fetching the container with ID {id}"
            raise Vault.LoadVaultError(msg)

    def load_from_file(self, path: str):
        """
        Load the vault from a file

        :param str path: path to json file
        :raise LoadVaultError: if file could not be loaded into the vault
        :raise FileNotFoundError: if the file was not found
        :raise PermissionError: if the file could not be read
        """

        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            msg = "Could not load vault: Invalid JSON (file may be corrupted/empty)"
            raise Vault.LoadVaultError(msg)

        try:
            containers = [
                Container.from_data(
                    self.master_password,
                    id,
                    base64.b64decode(c["ciphertext"]),
                    c["mac"],
                    base64.b64decode(c["key"]["salt"]),
                    base64.b64decode(c["key"]["iv"])
                )
                for id, c in data["containers"].items()
            ]
            mac = data["mac"]
            salt = base64.b64decode(data["key"]["salt"])
            iv = base64.b64decode(data["key"]["iv"])

            if len(salt) != SymmetricKey.SALT_SIZE or \
                    len(iv) != SymmetricKey.BLOCK_SIZE:
                msg = "Could not load vault: Invalid salt or iv"
                raise Vault.LoadVaultError(msg)

            key = SymmetricKey(salt, iv)

            container_macs = [c["mac"]
                              for c_id, c in sorted(data["containers"].items())]
            computed_mac = hmac.new(
                key.generate_aes_key(self.master_password),
                "".join(container_macs).encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(computed_mac, mac):
                msg = "Integrity Error: Invalid vault MAC.\nThe vault may have been tampered with."
                raise Vault.LoadVaultError(msg)

            containers_map = {c.get_id(): c for c in containers}
            self.hidden_containers = {
                id: c for id, c in containers_map.items() if id < 0
            }
            self.containers = {
                id: c for id, c in containers_map.items() if id >= 0
            }
            self.key = key

        except Vault.LoadVaultError as e:
            raise e

        except Exception as e:
            msg = "Could not load vault: Password may be incorrect or the file may have been tampered with."
            raise Vault.LoadVaultError(msg)

    def save_to_file(self, path: str):
        """
        Save the vault to a file

        :param str path: path to json file
        :raise PermissionError: if the file could not be written
        """
        data = self.encrypt()
        json_dump = json.dumps(data, indent=4)
        with open(path, "w") as f:
            f.write(json_dump)

    def start_cloud(self):
        """
        Start the cloud service

        :return: True if the cloud service was started, False otherwise
        """
        if self.cloud is not None:
            return True

        try:
            cred = self.hidden_containers[-1].get_data()
            if cred == "":
                return False
            cred = json.loads(cred)
        except Exception:
            return False

        try:
            token = self.hidden_containers[-2].get_data().strip()
            if token == "":
                token = None
            token = json.loads(token)
        except Exception:
            token = None

        self.cloud = GDrive(cred, token)
        self.hidden_containers[-2].set_data(self.cloud.token)
        return True

    def download_backup(self, filepath: str) -> bool:
        """
        Download backup from google drive

        :param str filepath: path to save the backup
        :return: True if the backup was downloaded, False otherwise
        """
        if self.start_cloud():
            return self.cloud.download_file(
                os.path.basename(filepath), filepath)
        return False

    def upload_backup(self, filepath: str) -> bool:
        """
        Upload existing save file to google drive.

        :param str filepath: path to the save file
        :return: True if the file was uploaded, False otherwise
        """
        if self.start_cloud():
            name = os.path.basename(filepath)
            return self.cloud.upload_file(filepath, f"{name}.BAK")
        return False

    def set_master_password(self, password: str):
        """
        Set the master password of the vault

        :param str password: new master password
        """
        self.master_password = password
        if self.cloud is not None:
            self.cloud.password = password
        self.regenerate_keys()

    def regenerate_keys(self):
        """
        Regenerate the key of the vault
        """
        self.key = SymmetricKey()
        for c in self.containers.values():
            c.key = SymmetricKey()
        for c in self.hidden_containers.values():
            c.key = SymmetricKey()

    def set_cloud_credentials(self, creds=None, token=None):
        """
        Set the credentials of the vault

        :param dict credentials: credentials to set
        """
        if creds is not None:
            self.hidden_containers[-1].set_data(creds)
        if token is not None:
            self.hidden_containers[-2].set_data(token)


class GDrive:
    """Class representing the Google Drive API"""

    SCOPES = ["https://www.googleapis.com/auth/drive.file"]

    def __init__(self, credential, token=None):
        self.credential = credential
        self.token = token

        token_cred = None
        if token is not None:
            token_cred = Credentials.from_authorized_user_info(
                token,
                GDrive.SCOPES
            )
        # If there are no (valid) credentials available, let the user log in.
        if not token_cred or not token_cred.valid:
            if token_cred and token_cred.expired and token_cred.refresh_token:
                token_cred.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    credential, GDrive.SCOPES
                )
                token_cred = flow.run_local_server(port=0)

        self.token = token_cred.to_json()

        self.service = build("drive", "v3", credentials=token_cred)

    def upload_file(self, filepath: str, name: str) -> bool:
        """
        Upload a file to Google Drive

        :param str filepath: file to upload
        :param str name: name of the file in Google Drive
        :return: True if the file was uploaded, False otherwise
        """
        file_metadata = {
            'name': name,
            'mimeType': '*/*'
        }
        media = MediaFileUpload(
            filepath,
            mimetype='*/*',
            resumable=True)
        try:
            self.service.files().create(
                body=file_metadata, media_body=media, fields='id'
            ).execute()
            return True
        except Exception:
            return False

    def download_file(self, name: str, filepath: str) -> bool:
        """
        Download a file from Google Drive. If multiple files with the same name
        exist, the most recent one is downloaded.

        :param str name: name of the file to download
        :param str filepath: path to save the file
        :return: True if the file was downloaded, False otherwise
        """
        try:
            service = self.service
            # Call the Drive v3 API
            # get date of last modification
            results = (
                service.files()
                .list(
                    q=f"name='{name}'",
                    spaces="drive",
                    orderBy="modifiedTime desc",
                    fields="files(id, name)",
                )
                .execute()
            )

            items = results.get("files", [])

            if not items:
                return False

            file_id = items[0]["id"]
            request = service.files().get_media(fileId=file_id)
            response = request.execute()

            if not response:
                return False

            with open(filepath, "wb") as f:
                f.write(response)
            return True

        except Exception:
            return False

    def delete_file(self, name: str) -> bool:
        """
        Delete a file from Google Drive

        :param str name: name of the file to delete
        :return: True if the file was deleted, False otherwise
        """
        try:
            service = self.service
            results = (
                service.files()
                .list(
                    q=f"name='{name}'",
                    spaces="drive",
                    fields="files(id, name)",
                )
                .execute()
            )

            items = results.get("files", [])

            if not items:
                return False

            file_id = items[0]["id"]
            service.files().delete(fileId=file_id).execute()
            return True

        except Exception:
            return False
