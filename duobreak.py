# SPDX-License-Identifier: AGPL-3.0-or-later

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
from pyzbar.pyzbar import decode as pyzbar_decode
import atexit
import base64
import datetime
import email.utils
import getpass
import json
import logging
import os
import pyotp
import requests
import shutil
import sys
import time
import urllib.parse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DuoAuthenticator:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config_version = 1
        self.config = {}
        self.encryption_key = None
        self.select_database()
        self.load_config()

        if "keys" not in self.config:
            self.config["keys"] = {}
            self.save_config()

    def derive_encryption_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return salt, kdf.derive(password.encode('utf-8'))

    def verify_encryption_key(self, key, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            kdf.verify(password.encode('utf-8'), key)
            return True
        except Exception:
            return False

    def encrypt_data(self, data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

    def decrypt_data(self, encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)

    def get_password(self, prompt):
        password = getpass.getpass(prompt)
        if len(password) < 8:
            logger.error("Password must be at least 8 characters long.")
            return self.get_password(prompt)
        return password

    def confirm_password(self, prompt):
        password = self.get_password(prompt)
        password_confirm = self.get_password("Confirm password: ")
        if password == password_confirm:
            return password
        else:
            print("Passwords do not match. Please try again.")
            return self.confirm_password(prompt)

    def select_database(self):
        duo_files = [f for f in os.listdir() if f.endswith(".duo")]
        if duo_files:
            print("Duo databases found:")
            for i, file in enumerate(duo_files, 1):
                print(f"{i}. {file}")
            while True:
                try:
                    choice = int(input("Enter the number corresponding to the database you want to use: "))
                    if 1 <= choice <= len(duo_files):
                        self.config_file = duo_files[choice - 1]
                        break
                    else:
                        print("Invalid input. Please enter a valid number.")
                except ValueError:
                    print("Invalid input. Please enter a valid number.")
        else:
            print("No Duo databases found. Creating a new database.")
            db_name = input("Enter a name for the new database: ").strip()
            self.config_file = f"{db_name}.duo"

    def change_password(self):
        password = self.confirm_password("Enter a new password for the database: ")
        salt, new_key = self.derive_encryption_key(password)
        decrypted_data = self.decrypt_data(self.config["encrypted_data"], self.encryption_key)
        self.config["encrypted_data"] = self.encrypt_data(decrypted_data, new_key)
        self.encryption_key = new_key
        self.save_config(salt=salt)  # Make sure that the salt is passed as a keyword argument
        print("Password changed successfully.")

    def load_config(self):
        attempts = 0
        while attempts < 3:
            if os.path.exists(self.config_file):
                print("Ready for password input.")
                password = self.get_password("Enter the password to unlock your vault: ")
                with open(self.config_file, "rb") as f:
                    version, salt, encrypted_data = f.read(4), f.read(16), f.read()
                    if version != b'DBv1':
                        logger.error("Unsupported configuration file version. Exiting...")
                        sys.exit(1)

                    self.encryption_key = self.derive_encryption_key(password, salt)[1]
                    if self.verify_encryption_key(self.encryption_key, password, salt):
                        try:
                            self.config["encrypted_data"] = encrypted_data
                            decrypted_data = self.decrypt_data(encrypted_data, self.encryption_key)
                            self.config.update(json.loads(decrypted_data))
                            break
                        except ValueError as e:
                            logger.error("Incorrect password or corrupted data. Please try again.")
                            attempts += 1
                    else:
                        logger.error("Incorrect password. Please try again.")
                        attempts += 1
            else:
                print("Ready for password input.")
                password = self.confirm_password("Enter a password to create a new vault: ")
                salt, self.encryption_key = self.derive_encryption_key(password)
                self.config = {"keys": {}}
                self.save_config(salt)
        if attempts >= 3:
            logger.error("Reached maximum password attempts. Exiting...")
            sys.exit(1)

    def import_key(self, keyfile):
        try:
            self.pubkey = RSA.import_key(keyfile.encode('utf-8'))
        except ValueError:
            with open(keyfile, "rb") as f:
                self.pubkey = RSA.import_key(f.read())

    def save_config(self, salt=None):
        if salt is None:
            with open(self.config_file, "rb") as f:
                version, salt = f.read(4), f.read(16)

        # Temporarily remove the 'encrypted_data' key from the config dictionary, if it exists
        encrypted_data = self.config.pop("encrypted_data", None)

        # Save the config dictionary without the 'encrypted_data' key to a temporary file
        temp_file = self.config_file + ".tmp"
        with open(temp_file, "wb") as f:
            data_to_save = json.dumps(self.config).encode("utf-8")
            encrypted_data_to_save = self.encrypt_data(data_to_save, self.encryption_key)
            f.write(b'DBv1' + salt + encrypted_data_to_save)

        # Replace the original Duo file with the temporary file
        shutil.move(temp_file, self.config_file)

        # Restore the 'encrypted_data' key to the config dictionary, if it was removed
        if encrypted_data is not None:
            self.config["encrypted_data"] = encrypted_data

    def prompt_qr_code(self):
        print("Please provide the QR code image file path (leave empty to cancel):")
        file_path = input().strip()
        if not file_path:
            return None
        if os.path.exists(file_path):
            return file_path
        else:
            print("Invalid file path. Please try again.")
        return self.prompt_qr_code()

    def parse_qr_code(self, file_path):
        img = Image.open(file_path)

        decoded_data = pyzbar_decode(img)
        if decoded_data:
            qr_data = decoded_data[0].data.decode()
            code, host = map(lambda x: x.strip("<>"), qr_data.split("-"))
            missing_padding = len(host) % 4
            if missing_padding:
                host += "=" * (4 - missing_padding)
            return code, base64.b64decode(host.encode("ascii")).decode("ascii")
        else:
            print("Error: Could not decode the QR code. Please try again.")
            return None

    def activate(self, code, host):
        url = f"https://{host}/push/v2/activation/{code}?customer_protocol=1"
        headers = {
            "User-Agent": "okhttp/2.7.5"
        }
        key_pair = RSA.generate(2048)
        pubkey_data = key_pair.publickey().export_key("PEM").decode('ascii')
        privkey_data = key_pair.export_key("PEM").decode('ascii')
        data = {
            "pubkey": pubkey_data,
            "pkpush": "rsa-sha512"
        }

        r = requests.post(url, headers=headers, data=data)
        response = r.json()

        if "response" in response:
            return response["response"], pubkey_data, privkey_data
        else:
            print("Error during activation. Please try again.")
            print(f"Server response: {response}")
            sys.exit(1)

    def generate_signature(self, method, path, time, data, key_config):
        message = (time + "\n" + method + "\n" + key_config["host"].lower() + "\n" +
                   path + '\n' + urllib.parse.urlencode(data)).encode('ascii')

        h = SHA512.new(message)
        signature = pkcs1_15.new(self.pubkey).sign(h)
        auth = ("Basic " + base64.b64encode((key_config["response"]["pkey"] + ":" +
                                             base64.b64encode(signature).decode('ascii')).encode('ascii')).decode('ascii'))
        return auth

    def get_transactions(self, key_config):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions"
        data = {"akey": key_config["response"]["akey"], "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        signature = self.generate_signature("GET", path, time, data, key_config)
        r = requests.get(f"https://{key_config['host']}{path}", params=data, headers={
            "Authorization": signature, "x-duo-date": time, "host": key_config['host']})

        return r.json()

    def reply_transaction(self, transaction_id, answer, key_config):
        dt = datetime.datetime.utcnow()
        time = email.utils.format_datetime(dt)
        path = "/push/v2/device/transactions/" + transaction_id
        data = {"akey": key_config["response"]["akey"], "answer": answer, "fips_status": "1",
                "hsm_status": "true", "pkpush": "rsa-sha512"}

        signature = self.generate_signature("POST", path, time, data, key_config)
        r = requests.post(f"https://{key_config['host']}{path}", data=data, headers={"Authorization": signature, "x-duo-date": time, "host": key_config['host'], "txId": transaction_id})

        return r.json()

    def approve_push_notifications(self, key_name):
        key_config = self.config["keys"][key_name]
        self.import_key(key_config["privkey"])

        if "response" in key_config:
            failed_attempts = 0
            while True:
                if failed_attempts >= 10:
                    print("Reached 10 failed attempts. Returning to previous menu...")
                    break

                try:
                    r = self.get_transactions(key_config)
                except requests.exceptions.ConnectionError:
                    print("Connection Error")
                    time.sleep(5)
                    continue

                approved = False

                if "response" in r and "transactions" in r["response"]:
                    transactions = r["response"]["transactions"]
                    print("Checking for transactions")
                    if transactions:
                        for tx in transactions:
                            print(tx)
                            reply = self.reply_transaction(tx["urgid"], 'approve', key_config)
                            approved = True
                            break
                        if approved:
                            print("Transaction approved. Returning to previous menu...")
                            break
                    else:
                        print("No transactions")
                        failed_attempts += 1
                else:
                    print(f"Error fetching transactions. Server response: {r}. Retrying...")
                    failed_attempts += 1

                time.sleep(10)
        else:
            print("Error: Activation response is missing. Please try again.")
            sys.exit(1)

    def show_recent_hotp_codes(self, key_name, count=10):
        if "hotp_log" in self.config["keys"][key_name]:
            recent_codes = self.config["keys"][key_name]["hotp_log"][-count:]
            print(f"Last {count} HOTP codes for {key_name}:")
            for code in recent_codes:
                print(code)
        else:
            print(f"No recent HOTP codes found for {key_name}.")

    def authenticate(self, key_name):
        if key_name in self.config["keys"]:
            print("Select authentication method:")
            print("1. Duo Push")
            print("2. HOTP")
            print("3. Show recent HOTP codes")
            auth_method = input("Enter the number (1, 2, or 3) corresponding to the method you want to use: ")

            if auth_method == "1":
                self.approve_push_notifications(key_name)
            elif auth_method == "2":
                response = self.config["keys"][key_name]["response"]
                hotp_secret = base64.b32encode(response["hotp_secret"].encode("ascii")).decode("ascii")
                hotp = pyotp.HOTP(hotp_secret)

                if "hotp_counter" in self.config["keys"][key_name]:
                    self.config["keys"][key_name]["hotp_counter"] += 1
                else:
                    self.config["keys"][key_name]["hotp_counter"] = 1

                if "hotp_log" not in self.config["keys"][key_name]:
                    self.config["keys"][key_name]["hotp_log"] = []

                hotp_code = hotp.at(self.config["keys"][key_name]["hotp_counter"])
                print(f"Generated HOTP code: {hotp_code}")

                self.config["keys"][key_name]["hotp_log"].append(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} ({key_name}): {hotp_code}")
                self.save_config()
            elif auth_method == "3":
                self.show_recent_hotp_codes(key_name)
            else:
                print("Invalid input. Please try again.")
                self.authenticate(key_name)
        else:
            print("Error: Key not found. Please try again.")
            sys.exit(1)

    def main_menu(self):
        while True:
            print("\nMain Menu:")
            print("1. Add a new key")
            print("2. Delete a key")
            print("3. List keys")
            print("4. Authenticate")
            print("5. Change password")
            print("6. Exit")

            choice = input("Enter the number (1, 2, 3, 4, 5, or 6) corresponding to the action you want to perform: ")

            if choice == "1":
                self.add_key()
            elif choice == "2":
                self.delete_key()
            elif choice == "3":
                self.list_keys()
            elif choice == "4":
                self.authenticate_key()
            elif choice == "5":
                self.change_password()
            elif choice == "6":
                print("Exiting...")
                self.save_config()
                sys.exit(0)
            else:
                print("Invalid input. Please try again.")

    def add_key(self):
        while True:
            key_name = input("Enter a nickname for the new key (leave empty to cancel): ").strip()
            if not key_name:
                print("Returning to the main menu.")
                break
            if key_name not in self.config["keys"]:
                qr_file_path = self.prompt_qr_code()
                if qr_file_path is not None:
                    parsed_data = self.parse_qr_code(qr_file_path)
                    if parsed_data is not None:
                        code, host = parsed_data
                        response, pubkey, privkey = self.activate(code, host)
                        self.config["keys"][key_name] = {"code": code, "host": host, "response": response, "pubkey": pubkey, "privkey": privkey}
                        self.save_config()
                        print(f"Key '{key_name}' added successfully.")
                    else:
                        print("Could not add the key. Returning to the main menu.")
                else:
                    print("No QR code file provided. Returning to the main menu.")
                break
            else:
                print("Error: Key with the same name already exists. Please try again.")

    def delete_key(self):
        key_name = input("Enter the nickname of the key you want to delete: ")
        if key_name in self.config["keys"]:
            del self.config["keys"][key_name]
            self.save_config()
            print(f"Key '{key_name}' deleted successfully.")
        else:
            print("Error: Key not found. Please try again.")

    def list_keys(self):
        print("Keys:")
        for key_name in self.config["keys"]:
            print(f"- {key_name} ({self.config['keys'][key_name]['response']['customer_name']})")

    def authenticate_key(self):
        key_name = input("Enter the nickname of the key you want to use for authentication: ")
        if key_name in self.config["keys"]:
            self.authenticate(key_name)
        else:
            print("Error: Key not found. Please try again.")

    def delete_encryption_key_from_memory(self):
        self.encryption_key = None


if __name__ == "__main__":
    authenticator = DuoAuthenticator()
    atexit.register(authenticator.delete_encryption_key_from_memory)
    authenticator.main_menu()
