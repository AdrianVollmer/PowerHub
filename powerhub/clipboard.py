class Clipboard(object):
    def __init__(self):
        self.entries = []

    def __iter__(self):
        return iter(self.entries)

    def add(self, content, time, IP):
        e = ClipboardEntry(content, time, IP)
        self.entries.append(e)
        return e

    def delete(self, n):
        self.entries.pop(n)
        return


class ClipboardEntry(object):
    def __init__(self, content, time, IP):
        self.content = content
        self.time = time
        self.IP = IP

    def __str__(self):
        return self.content


clipboard = Clipboard()
