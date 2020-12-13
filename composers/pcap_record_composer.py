import struct


class PcapRecordComposer:
    def __init__(self, data: bytes, time_in_seconds: float):
        self.data = data
        self.seconds = int(time_in_seconds)
        self.microseconds = (time_in_seconds - self.seconds) * 1000

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
