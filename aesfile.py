from utilities import aes


class encFile:
    def __iter__(self):
        self._line_index = 0
        return self

    def __enter__(self):
        # Open and read contents of encrypted file
        newfile = False
        try:

            self._file_object = open(self._filename, "rb")
            self._enc_contents = self._file_object.read()
        except FileNotFoundError:
            newfile = True

        if not newfile:
            # Process the encrypted data into raw arrays

            self._raw_contents = aes.decrypt_bytes(
                self._enc_contents, self._key, self._iv
            )  # DECRYPT HERE
            self._contents = bytearray(self._raw_contents).decode()
            self._contents = self._contents.split("\n")
            self._contents = list(map(lambda x: x.split(","), self._contents))

            # Cleanup
            self._file_object.close()
            self._raw_contents = "\x00" * len(
                self._raw_contents
            )  # Overwrite the memory so it does not persist
            del self._raw_contents

        else:
            self._contents = []

        return self

    def __init__(self, filename, key, iv):
        self._filename = filename
        self._key = key
        self._iv = iv

    def __exit__(self, exc_type, exc_val, exc_tb):

        self._file_object = open(self._filename, "wb")
        self._contents = [[str(x) for x in i] for i in self._contents]
        self._contents = map(lambda x: ",".join(x), self._contents)
        self._contents = "\n".join(self._contents)
        self._contents = self._contents.encode()
        self._enc_contents = aes.encrypt_bytes(
            self._contents, self._key, self._iv
        )  # ENCRYPT HERE
        self._file_object.write(bytearray(self._enc_contents))

        self._file_object.close()

        del self._contents

    def __next__(self):
        if self._line_index < len(self._contents):
            line = self._contents[self._line_index]
            self._line_index += 1
            return line
        else:
            raise StopIteration

    def writerow(self, row):
        self._contents.append(row)