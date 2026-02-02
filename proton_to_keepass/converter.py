import gnupg
import json
from proton_to_keepass.entry import Entry
from proton_to_keepass.config import Config

class Converter():
  def __init__ (self, config: Config):
    self.gpg = gnupg.GPG(config.gnupg_path)
    self.filepath = config.encrypted_file_path
    self.passphrase = config.encrypted_file_passkey
    self.decrypted_file = None
    self.vaults = None
  
  def decrypt_file_to_json(self):
    decrypted_result = self.gpg.decrypt_file(self.filepath, passphrase=self.passphrase)
    if decrypted_result.status == "bad passphrase" or decrypted_result.status == "decryption failed":
      print(f"   GnuPG Status: {decrypted_result.status}")
      print("   Error: Possible bad passphrase, try again.")
      exit()

    cleaned_text = self.strip_junk(decrypted_result.data)
    decoder = json.JSONDecoder()
    self.decrypted_file, _ = decoder.raw_decode(cleaned_text)
    self.vaults = self.decrypted_file["vaults"].items()

  def strip_junk(self, raw_bytes):
    text = raw_bytes.decode("utf-8", errors="ignore")
    start = text.find("{")
    if start == -1:
      print("   Error: Unable to locate JSON in decrypted file.")
      exit()
    return text[start:]

  def create_entry(self, entry):
    return Entry(entry)

  
