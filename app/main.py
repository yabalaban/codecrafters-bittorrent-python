import json
import sys
import hashlib
import requests


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


class TorrentFile: 
    def __init__(self, file_bytes: bytearray):
        val, _ = decode_bencode(file_bytes, 0)
        self.url = val["announce"].decode()
        self.length = val["info"]["length"]
        info_bencode = encode_bencode(val['info'])
        self.info_hash = hashlib.sha1(info_bencode).hexdigest()
        self.piece_length = val["info"]["piece length"] 
        pieces = val["info"]["pieces"] 
        self.piece_hashes = [pieces[i:i + 20].hex() for i in range(0, len(pieces), 20)]

    def __repr__(self):
        details = """Tracker URL: {}
Length: {}
Info Hash: {}
Piece Length: {}
Piece Hashes:""".format(self.url, self.length, self.info_hash, self.piece_length)
        for hash in self.piece_hashes:
            details += "\n" 
            details += hash 
        return details


def query_tracker(file: TorrentFile):
    params = {
        "info_hash": bytes.fromhex(file.info_hash),
        "peer_id": "55112233445566778899", # randomize later 
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": file.length,
        "compact": 1
    }
    response = requests.get(file.url, params)  
    data, _ = decode_bencode(response.content, 0)
    peers = []
    for pdata in [data['peers'][i:i + 6] for i in range(0, len(data['peers']), 6)]:
        port = int.from_bytes(pdata[4:], "big")
        peer = '.'.join([str(p) for p in pdata[:4]]) + ':' + str(port)
        peers.append(peer)
    return peers


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
            file = TorrentFile(bencoded_value)
            print(file)
    elif command == "peers":
        file_path = sys.argv[2].encode()

        with open(file_path, 'rb') as f:
            bencoded_value = f.read()
            file = TorrentFile(bencoded_value)
            print("\n".join(query_tracker(file)))

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
