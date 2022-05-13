import struct
import serialization

class Request:
    def __init__(self, function: bytes, param: bytes, dry_run: bool):
        self.function = function
        self.param = param
        self.dry_run = dry_run

    def pack(self) -> bytes:
        ret = bytes()
        ret += serialization.pack(self.function)
        ret += serialization.pack(self.param)
        ret += serialization.pack(self.dry_run)
        return ret

class Response:
    def __init__(self, success: dict, failure: int):
        self.success = success
        self.failure = failure

        if self.success is None == self.failure is None:
            raise ValueError('Response cannot be both success or failure')

    @classmethod
    def unpack(cls, buf: bytes):
        print('unpacking result from {} bytes'.format(len(buf)))
        (success_or_failure,) = struct.unpack('B', buf[:1])
        if success_or_failure == 0:
            updates = serialization.unpack(dict, buf[1:])
            return cls(updates, None)
        elif success_or_failure == 1:
            (error_code,) = struct.unpack('B', buf[1:])
            return cls(None, error_code)
        else:
            raise ValueError('Invalid response', success_or_failure)
