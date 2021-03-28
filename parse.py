#!/usr/bin/env python3


class ParseWarning(Warning):
    def __init__(self, parser, message):
        super().__init__(f"{parser.name}, line {parser.line}: {message}")


class Parser:
    def __init__(self, data, namespace):
        self.data = data
        self.name = namespace
        self.line = 1

    def parse(self):
        for cipher_raw in self.data.split(sep="\n\n"):

            cipher_data = dict()
            for attr in cipher_raw.splitlines():

                key, sep, value = attr.partition(":")
                if sep != ":":
                    raise ParseWarning(self, "No key/value separator found.")
                key, value = key.strip(), value.strip()

                if key in cipher_data:
                    raise ParseWarning(self, f"Duplicate key definition ({key}).")

                cipher_data[key] = value

                self.line += 1

            if (len(cipher_data) == 0):
                continue

            if ("name" not in cipher_data):
                raise ParseWarning(self, "Cipher name not specified.")

            yield Cipher(**cipher_data)


class Cipher:
    def __init__(self, name, **params):
        self.name = name
        self.dict = {"name": name}
        self.dict.update(params)

    def __str__(self):
        out = []
        for k, v in self.dict.items():
            out.append(f"{k:13}: {v}")
        out.append("")

        return "\n".join(out)

    def keys(self):
        return self.dict.keys()
    fields = keys


def main():
    from sys import argv, stderr

    POSSIBLE_KEYS = [
        "async",
        "blocksize",
        "chunksize",
        "digestsize",
        "driver",
        "geniv",
        "internal",
        "ivsize",
        "maxauthsize",
        "max keysize",
        "min keysize",
        "module",
        "name",
        "priority",
        "refcnt",
        "seedsize",
        "selftest",
        "type",
        "walksize"]

    KNOWN_TYPES = [
        "cipher",
        "ablkcipher",
        "akcipher",
        "blkcipher",
        "givcipher",
        "skcipher",
        "aead",
        "nivaead",
        "ahash",
        "shash",
        "compression",
        "digest",
        "kpp",
        "pcomp",
        "scomp",
        "rng"]


    ciphers = []

    for filename in argv[1:]:
        with open(filename, "r") as file:
            parser = Parser(file.read(), filename)
            ciphers.extend(parser.parse())

    # Create the table
    table = dict()
    for type in KNOWN_TYPES:
        table[type] = dict()
        for field in POSSIBLE_KEYS:
            # [0] - All ciphers of type have this field
            # [1] - No  ciphers of type have this field
            table[type][field] = [True, True]

    for cipher in ciphers:

        # Check if all ciphers contain only known fields
        if not all(map(POSSIBLE_KEYS.__contains__, cipher.keys())):
            print(f"cipher {cipher.name} contains an unknown field.", cipher,
                  file=stderr, sep='\n')

        # Check if all cipher types are known
        if cipher.dict["type"] not in KNOWN_TYPES:
            print(f"cipher {cipher.name} contains is of unknown type "
                  f"({cipher.dict['type']}).", cipher,
                  file=stderr, sep='\n')

        # Populate the table
        for field in POSSIBLE_KEYS:
            if field in cipher.keys():
                table[cipher.dict["type"]][field][1] = False
            else:
                table[cipher.dict["type"]][field][0] = False

    # Print table header
    print(f"|type/field |", end="")
    for field in POSSIBLE_KEYS:
        print(f"{field}|", end="")
    print(f"\n|-----------|", end="")
    for field in POSSIBLE_KEYS:
        print(f":{'-'*(len(field)-2)}:|", end="")
    print()

    # Print the table
    for type, fields in table.items():
        print(f"|{type:11}|", end="")
        for field in POSSIBLE_KEYS:
            if fields[field] == [False, False]:  out = '.'
            elif fields[field] == [True, False]: out = '✔'
            elif fields[field] == [False, True]: out = '✕'
            else:                                out = ' '
            print(f"{out:{len(field)}}|", end="")
        print()


if __name__ == "__main__":
    main()
