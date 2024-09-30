from enum import Enum

import json
from multiprocessing.pool import ThreadPool
import sys
import hashlib
import requests
import socket
import os


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


class BitTorrentHandshakeMessage:
    def __init__(self, payload: bytearray):
        self.payload = payload

    @property
    def info_hash(self) -> str:
        return self.payload[28:48].hex()
    
    @property
    def peer_id(self) -> str:
        return self.payload[48:].hex()

    @staticmethod
    def make(info_hash: bytearray, peer_id: bytearray):
        packet = bytearray()
        packet.append(19) # proocol length 
        packet.extend(b'BitTorrent protocol')
        packet.extend(bytearray(8))
        packet.extend(info_hash)
        packet.extend(peer_id)
        return BitTorrentHandshakeMessage(packet)
    
    def __repr__(self):
        return f"Handshake({self.info_hash=}, {self.peer_id=})"
    

class BitTorrentPeerMessageID(Enum):
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOT_INTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8
    UNKNOWN = 99


class BitTorrentPeerMessage:
    def __init__(self, packet: bytearray):
        self.packet = packet

    @property
    def message_id(self) -> BitTorrentPeerMessageID:
        try:
            return BitTorrentPeerMessageID(self.packet[4])
        except:
            print("> unknown message", self.packet)
            return BitTorrentPeerMessageID.UNKNOWN
    
    @property
    def payload(self) -> bytearray:
        return self.packet[5:]
    
    @property
    def prefix(self) -> bytearray:
        return int.from_bytes(self.packet[:4], "big")

    @staticmethod
    def make(message_id: BitTorrentPeerMessageID, payload: bytearray):
        packet = bytearray()
        packet.extend((len(payload) + 1).to_bytes(length=4, byteorder='big')) 
        packet.append(message_id.value)
        packet.extend(payload)
        return BitTorrentPeerMessage(packet)
    
    def __repr__(self):
        return f"Peer({self.message_id=}, {self.payload=})"


def tcp_handshake(file: TorrentFile, peer: str):
    host, port = str(peer, encoding='utf-8').split(':')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))

    message = BitTorrentHandshakeMessage.make(bytes.fromhex(file.info_hash), bytes.fromhex(os.urandom(20).hex()))
    s.sendall(message.payload)
    
    data = s.recv(68)
    msg = BitTorrentHandshakeMessage(data)

    return (s, msg)


def receive_message(socket) -> BitTorrentPeerMessage:
    data = bytearray()
    prefix = socket.recv(4)
    msg_len = int.from_bytes(prefix, "big")
    data.extend(prefix)

    remaining = msg_len
    while len(data) < (msg_len + 4):
        chunk = socket.recv(min(2 ** 14, remaining))
        data.extend(chunk)
        remaining -= len(chunk)

    return BitTorrentPeerMessage(data)


def download_piece(file: TorrentFile, idx: int, peer: str) -> bytearray:
    piece_length = file.piece_length if idx < (len(file.piece_hashes) - 1) else file.length % file.piece_length
    blocks_n = piece_length // (2 ** 14) + 1
    piece = bytearray(piece_length)
    scheduled = 0
    received = 0
    socket, msg = tcp_handshake(file, bytes(peer, encoding='utf-8'))
    
    while True:
        msg = receive_message(socket)
            
        if msg.message_id == BitTorrentPeerMessageID.BITFIELD:
            reply = BitTorrentPeerMessage.make(BitTorrentPeerMessageID.INTERESTED, bytearray())
            socket.sendall(reply.packet)
        elif msg.message_id == BitTorrentPeerMessageID.UNCHOKE:
            packets = [] 
            for i in range(blocks_n): 
                payload = bytearray()
                begin = i * (2 ** 14)
                block = 2 ** 14 if i < blocks_n - 1 else piece_length % (2 ** 14)
                if block == 0:
                    continue
                payload.extend(idx.to_bytes(4, byteorder='big'))
                payload.extend(begin.to_bytes(4, byteorder='big'))
                payload.extend(block.to_bytes(4, byteorder='big'))
                reply = BitTorrentPeerMessage.make(BitTorrentPeerMessageID.REQUEST, payload)
                packets.append(reply.packet)
            scheduled = len(packets)
            [socket.sendall(p) for p in packets]
        elif msg.message_id == BitTorrentPeerMessageID.PIECE:
            begin = int.from_bytes(msg.payload[4:8], "big")
            block = msg.payload[8:]
            piece[begin:begin + len(block)] = block
            received += 1
            if received == scheduled:
                break
    socket.close()

    assert(hashlib.sha1(piece).hexdigest() == file.piece_hashes[idx])
    return piece


def download_piece_(file: TorrentFile, idx: int) -> bytearray:
    peers = query_tracker(file)
    peer = peers[1]
    return download_piece(file, idx, peer)


def download(file: TorrentFile) -> list[bytearray]:
    peers = query_tracker(file)
    pool = ThreadPool()

    def runner(args):
        pieces = {}
        for i in args[1]: 
            pieces[i] = download_piece(args[0], i, args[2])
        return pieces

    idxs = list(range(len(file.piece_hashes)))
    args = [[file, idxs[:len(idxs) // 2], peers[1]], [file, idxs[len(idxs) // 2:], peers[2]]]

    results = pool.map(runner, args)
    results = {k: v for d in results for k, v in d.items()}

    f = bytearray()
    for i in idxs:
        f.extend(results[i])
    return f


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
    elif command == "handshake":
        file_path = sys.argv[2].encode()
        address = sys.argv[3].encode()

        with open(file_path, 'rb') as f:
            bencoded_value = f.read()
            file = TorrentFile(bencoded_value)
            _, message = tcp_handshake(file, address)
            print("Peer ID: {}".format(message.peer_id))
    elif command == "download_piece":
        output_path = sys.argv[3].encode()
        file_path = sys.argv[4].encode()
        idx = int(sys.argv[5].encode())

        with open(file_path, 'rb') as f:
            bencoded_value = f.read()
            file = TorrentFile(bencoded_value)
            piece = download_piece_(file, idx)
            with open(output_path, 'wb') as o:
                o.write(piece)
    elif command == "download":
        output_path = sys.argv[3].encode()
        file_path = sys.argv[4].encode()

        with open(file_path, 'rb') as f:
            bencoded_value = f.read()
            file = TorrentFile(bencoded_value)
            piece = download(file)
            with open(output_path, 'wb') as o:
                o.write(piece)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
