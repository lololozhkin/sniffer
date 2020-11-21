import struct


class PcapRecordComposer:
    def __init__(self, data: bytes, seconds, microseconds):
        self.data = data
        self.seconds = seconds
        self.microseconds = microseconds

    def compose(self):
        data_len = len(self.data)
        file_len = len(self.data)
        header = struct.pack(
            '<IIII',
            int(self.seconds),
            int(self.microseconds),
            data_len,
            file_len
        )
        return header + self.data
