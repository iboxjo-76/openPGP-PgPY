import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

class GenOpenpgpKey:
    def __init__(self):
        self.global_key = None
        self.public_key = None
        self.private_key = None
        self.key = None
        self.uid = None

    def set_key(self,key):
        self.global_key = key
    def get_key(self):
        return self.global_key
    def save_key(self,name):
        '''
        сохранение ключей в файлы
        '''
        with open(name + '.prv', "w") as f:
            f.writelines(str(self.private_key_out()))
        with open(name + '.pub', "w") as f:
            f.writelines(str(self.public_key_out()))
    def open_key(self,name):
        with open(name + '.prv', "r") as f:
            self.set_key(f.read())

    def private_key_out(self):
        '''
        получить приватный ключ
        :return: prv key
        '''
        self.private_key = str(self.global_key)
        return self.private_key
    def public_key_out(self):
        '''
        получить публичный ключ
        :return: pub key
        '''
        self.public_key = str(self.global_key.pubkey)
        return self.public_key

    def gen_keys(self,usr, comment, email):
        """
        Метод, генерирующий открытый и закрытый ключи.
        """
        self.key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        # Теперь у нас есть материал ключа. Однако поскольку у нового ключа отсутствует ID пользователя, то к работе он пока не готов!
        self.uid = pgpy.PGPUID.new(usr, comment, email)

        # Мы должны добавить ключу новый ID пользователя и указать на этом этапе все установочные параметры,
        # поскольку на данный момент PGPy не имеет встроенных установочных параметров ключей по умолчанию.
        # Этот пример похож на предустановленные настройки GnuPG 2.1.x, без срока действия и предпочитаемого сервера ключей
        self.key.add_uid(self.uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP,
                                 CompressionAlgorithm.Uncompressed])
        self.set_key(self.key)
        return self.key

# Использование класса
if __name__ == "__main__":
    name_i = 'Master'
    comment_i = 'Best Key'
    email_i = 'iboxjo@yandex.ru'
    keys = GenOpenpgpKey()
    keys.gen_keys(name_i,comment_i,email_i)
    keys.save_key(name_i)
    print(keys.private_key_out())
    print(keys.public_key_out())

