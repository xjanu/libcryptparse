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


def main():
    from sys import argv

    ciphers = []

    for filename in argv[1:]:
        with open(filename, "r") as file:
            parser = Parser(file.read(), filename)
            ciphers.extend(parser.parse())

    for cipher in ciphers:
        # Edit filters here, too lazy to implement cmdline parsing
        if "cipher" in cipher.dict["type"]:
            print(cipher)


if __name__ == "__main__":
    main()
