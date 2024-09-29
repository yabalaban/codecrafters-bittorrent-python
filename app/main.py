import json
import sys
import hashlib


def decode_bencode(value: bytes, offset: int): 
    def _parse_number() -> int:
        nonlocal offset
        val = 0 
        while chr(value[offset]).isdigit():
            val *= 10
            val += int(chr(value[offset]))
            offset += 1
        return val 
        
    def decode_integer() -> int:
        nonlocal offset
        # skip 'i'
        offset += 1
        negate = False 
        if value[offset] == ord('-'):
            negate = True
            offset += 1
        val = _parse_number()
        # skip 'e'
        offset += 1
        return val * -1 if negate else val
        
    def decode_string() -> bytes:
        nonlocal offset
        l = _parse_number()
        # skip ':'
        offset += 1
        s = value[offset: offset + l]
        # skip str
        offset += l
        return s
        
    def decode_list() -> list[any]:
        nonlocal offset
        # skip 'l'
        offset += 1 
        l = [] 
        while value[offset] != ord('e'):
            val, offset = decode_bencode(value, offset)
            l.append(val) 
        # skip 'e' 
        offset += 1
        return l
        
    def decode_dict() -> dict[any, any]:
        nonlocal offset
        # skip 'd' 
        offset += 1 
        d = {} 
        while value[offset] != ord('e'):
            k, offset = decode_bencode(value, offset)
            v, offset = decode_bencode(value, offset)
            d[str(k, encoding='utf-8')] = v 
        # skip 'e'
        offset += 1 
        return d


    if value[offset] == ord('i'):
        return (decode_integer(), offset)
    elif value[offset] == ord('l'):
        return (decode_list(), offset)
    elif value[offset] == ord('d'):
        return (decode_dict(), offset)
    else: 
        return (decode_string(), offset)


def encode_bencode(value: any) -> bytearray:
    bencode = bytearray()

    if type(value) == dict: 
        bencode.append(ord('d'))
        for k, v in value.items():
            bencode.extend(encode_bencode(k))
            bencode.extend(encode_bencode(v))
        bencode.append(ord('e'))
    elif type(value) == list:
        bencode.append(ord('l'))
        for x in value:
            bencode.extend(encode_bencode(x)) 
        bencode.append(ord('e'))
    elif type(value) == str:
        bencode.extend(bytearray(str(len(value)), encoding='utf-8'))
        bencode.append(ord(':'))
        bencode.extend(bytes(value, encoding='utf-8'))
    elif type(value) == bytes or type(value) == bytearray: 
        bencode.extend(bytearray(str(len(value)), encoding='utf-8'))
        bencode.append(ord(':'))
        bencode.extend(value)
    else:
        bencode.extend(bytes('i{}e'.format(value), encoding='utf-8'))

    return bencode

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        val, _ = decode_bencode(bencoded_value, 0)
        print(json.dumps(val, default=bytes_to_str))
    elif command == "info":
        file_path = sys.argv[2].encode()

        with open(file_path, 'rb') as f:
            bencoded_value = f.read()
            val, _ = decode_bencode(bencoded_value, 0)
            url = val["announce"]
            l = val["info"]["length"]
            info_bencode = encode_bencode(val['info'])

            res = "Tracker URL: {}\nLength: {}\nInfo Hash: {}".format(str(url, encoding='utf-8'), l, hashlib.sha1(info_bencode).hexdigest())
            print(res)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
