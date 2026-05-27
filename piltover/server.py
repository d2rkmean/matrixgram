import os
import time
import asyncio
import secrets
import hashlib
import hmac

import tgcrypto

from types import SimpleNamespace
from io import BytesIO
from typing import Callable, Awaitable, Optional, cast
from collections import defaultdict

from loguru import logger
from icecream import ic

from piltover.enums import Transport
from piltover.exceptions import Disconnection, InvalidConstructor
from piltover.connection import Connection
from piltover.types import Keys
from piltover.tl.types import (
    Int32,
    Int64,
    CoreMessage,
    EncryptedMessage,
    DecryptedMessage,
    UnencryptedMessage,
)
from piltover.utils import (
    read_int,
    generate_large_prime,
    gen_keys,
    get_public_key_fingerprint,
    restore_private_key,
    restore_public_key,
    kdf
)
from piltover.utils.rsa_utils import rsa_pad_inverse
from piltover.utils.buffered_stream import BufferedStream
from piltover.tl import TL

TELEGRAM_DH_PRIME_HEX = (
    "C71CAE17114B10FA387EED98C1D3145444F141F3258F3025581792B7F9953F17"
    "94283455BB6D11B2FA3443FC2E06A26B35F20DF8B978F8CBE3921356AB7E6F4B"
    "FDE6F1CAC637C52DB8265005CF7A1F2E117E64FABA1E2FCDA36F6E60AFDC72A2"
    "6EF6BB78005E1BF3BF96F4B29DEFF8CEEE5ED57CBA7EE7A1CDE00A7DE1ECFF3B"
    "B0236021B9CD0AF4CCBE6DCAFE1B4957AE9F20CDEA79E3BCF986CE61BA64E68C"
    "8FCE45128D80F339B20A382AFE0D64F6DD016738CF15B804B749D7CBCE03CE91"
    "1FE5EED5FC44A999B0039EBEC1437CC3A2FA09E42F65646174EEB4EBBB9CC533"
    "89BD6EA407248CDDFEF5EFE7CB2FA5F67E2B3BB3FB658394F1A57EBFCDF13689"
)
TELEGRAM_DH_PRIME = int(TELEGRAM_DH_PRIME_HEX, 16)
TELEGRAM_DH_G = 3

HandlerFunc = Callable[["Client", CoreMessage, int], Awaitable[TL | dict | None]]
MiddlewareFunc = Callable[["Client", CoreMessage, int, HandlerFunc], Awaitable[TL | dict | None]]


class MatrixUpdateService:
    def __init__(self, server: "Server"):
        self.server = server
        self._running = False
        self._task: Optional[asyncio.Task] = None
        # TODO: Initialize your mautrix-python client here (e.g., MatrixClient)

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._update_loop())
        logger.info("MatrixUpdateService successfully started in background.")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            logger.info("MatrixUpdateService stopped.")

    async def _update_loop(self):
        # TODO: Start mautrix sync loop or register event handlers here.
        # If mautrix handles the loop internally, you can just forward events 
        # to self._broadcast_to_mtproto(sender, body) from your event listener.
        while self._running:
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in MatrixUpdateService loop: {e}")

    async def _broadcast_to_mtproto(self, sender: str, body: str):
        update_obj = TL.from_dict({
            "_": "updateShortMessage",
            "id": int(time.time()),
            "user_id": 123456, # TODO: Map Matrix sender to Telegram user_id
            "message": f"[{sender}] {body}",
            "date": int(time.time()),
            "pts": 1,
            "pts_count": 1
        })

        async with self.server.clients_lock:
            active_clients = list(self.server.clients.values())

        if not active_clients:
            return

        logger.info(f"Broadcasting Matrix event to {len(active_clients)} MTProto clients")
        for client in active_clients:
            if client.auth_data and getattr(client.auth_data, "auth_key", None) and client.last_session_id:
                try:
                    await client.send(update_obj, session_id=client.last_session_id)
                except Exception as e:
                    logger.error(f"Failed to send update to client {client.peerinfo}: {e}")


class Router:
    def __init__(self, prefix: str = ""):
        self.prefix = prefix
        self.handlers: defaultdict[str, list[HandlerFunc]] = defaultdict(list)
        self.middlewares: list[MiddlewareFunc] = []

    def on_message(self, typ: str):
        def decorator(func: HandlerFunc) -> HandlerFunc:
            self.add_handler(typ, func)
            return func
        return decorator

    def add_handler(self, typ: str, func: HandlerFunc) -> None:
        full_type = f"{self.prefix}.{typ}" if self.prefix else typ
        self.handlers[full_type].append(func)

    def middleware(self, func: MiddlewareFunc) -> MiddlewareFunc:
        self.middlewares.append(func)
        return func


class Server:
    HOST = "0.0.0.0"
    PORT = 4430

    def __init__(self, host: str = None, port: int = None, server_keys: Keys = None):
        self.host = host or self.HOST
        self.port = port or self.PORT
        self.server_keys = server_keys or gen_keys()

        self.public_key = restore_public_key(self.server_keys.public_key)
        self.private_key = restore_private_key(self.server_keys.private_key)
        self.fingerprint: int = get_public_key_fingerprint(self.server_keys.public_key)

        self.clients: dict[str, "Client"] = {}
        self.clients_lock = asyncio.Lock()
        self.auth_keys: dict[int, tuple[bytes, SimpleNamespace]] = {}

        self.handlers: defaultdict[str, list[HandlerFunc]] = defaultdict(list)
        self._middlewares: list[MiddlewareFunc] = []
        self.salt: int = 0

        self.update_service = MatrixUpdateService(self)

    def add_handler(self, typ: str, func: HandlerFunc) -> None:
        self.handlers[typ].append(func)

    def on_message(self, typ: str):
        def decorator(func: HandlerFunc) -> HandlerFunc:
            self.add_handler(typ, func)
            return func
        return decorator

    def add_middleware(self, func: MiddlewareFunc) -> None:
        self._middlewares.append(func)

    def middleware(self, func: MiddlewareFunc) -> MiddlewareFunc:
        self.add_middleware(func)
        return func

    def include_router(self, router: Router) -> None:
        for typ, funcs in router.handlers.items():
            for func in funcs:
                wrapped = self._wrap_with_middlewares(func, router.middlewares)
                self.add_handler(typ, wrapped)

    def _wrap_with_middlewares(self, handler: HandlerFunc, middlewares: list[MiddlewareFunc]) -> HandlerFunc:
        if not middlewares:
            return handler
        async def wrapped(client: "Client", message: CoreMessage, session_id: int):
            call_next = handler
            for mw in reversed(middlewares):
                _next, _mw = call_next, mw
                async def make_next(c, m, s, *, __next=_next, __mw=_mw):
                    return await __mw(c, m, s, __next)
                call_next = make_next
            return await call_next(client, message, session_id)
        return wrapped

    async def _dispatch(self, client: "Client", message: CoreMessage, session_id: int) -> TL | None:
        typ = message.obj._
        handlers = self.handlers.get(typ, [])
        handler_iter = iter(handlers)

        async def call_next_handler(c: "Client", m: CoreMessage, s: int) -> TL | dict | None:
            try:
                h = next(handler_iter)
            except StopIteration:
                return None
            result = await h(c, m, s)
            return await call_next_handler(c, m, s) if result is None else result
        
        final = call_next_handler
        for mw in reversed(self._middlewares):
            _next, _mw = final, mw
            async def make_global_next(c, m, s, *, __next=_next, __mw=_mw):
                return await __mw(c, m, s, __next)
            final = make_global_next

        return await final(client, message, session_id)

    @logger.catch
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_id = None
        try:
            stream = BufferedStream(reader=reader, writer=writer)
            extra = writer.get_extra_info("peername")
            header = await stream.peek(1)

            transport = await self._parse_transport(header, stream)
            if not transport:
                logger.error(f"Unknown transport type from {extra}")
                return

            client = Client(transport=transport, server=self, stream=stream, peerinfo=extra)
            client_id = f"{extra[0]}:{extra[1]}"
            
            async with self.clients_lock:
                self.clients[client_id] = client

            logger.info(f"Client connected via {transport} [{client_id}]")
            await client.worker()

        except Disconnection:
            logger.info(f"Client {client_id} disconnected.")
        except Exception as e:
            logger.exception(f"Error handling client {client_id}: {e}")
        finally:
            if client_id:
                async with self.clients_lock:
                    self.clients.pop(client_id, None)

    async def _parse_transport(self, header: bytes, stream: BufferedStream) -> Optional[Transport]:
        if header == b"\xef":
            await stream.read(1)
            return Transport.Abridged
        elif header == b"\xee":
            await stream.read(1)
            if await stream.read(3) == b"\xee\xee\xee":
                return Transport.Intermediate
        elif header == b"\xdd":
            await stream.read(1)
            if await stream.read(3) == b"\xdd\xdd\xdd":
                return Transport.PaddedIntermediate
        else:
            soon = await stream.peek(8)
            if soon[-4:] == b"\0\0\0\0":
                return Transport.Full
            return Transport.Obfuscated
        return None

    async def serve(self):
        await self.update_service.start()
        
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        logger.info(f"MTProto server started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def register_auth_key(self, auth_key_id: int, auth_key: bytes, shared: SimpleNamespace):
        self.auth_keys[auth_key_id] = (auth_key, shared)

    async def get_auth_key(self, auth_key_id: int) -> Optional[tuple[bytes, SimpleNamespace]]:
        return self.auth_keys.get(auth_key_id, None)


class Client:
    def __init__(self, server: Server, transport: Transport, stream: BufferedStream, peerinfo: tuple):
        self.server: Server = server
        self.peerinfo: tuple = peerinfo
        self.conn: Connection = Connection.new(transport=transport, stream=stream)

        self.auth_data: Optional[SimpleNamespace] = None
        self.seen_msg_ids = set()
        self.last_session_id: Optional[int] = None

        self._msg_id_last_time = 0
        self._msg_id_offset = 0
        self._incoming_content_related_msgs = 0
        self._outgoing_content_related_msgs = 0

    async def read_message(self) -> EncryptedMessage | UnencryptedMessage:
        data = BytesIO(await self.conn.recv())
        auth_key_id = read_int(data.read(8))
        if auth_key_id == 0:
            message_id = read_int(data.read(8))
            message_data_length = read_int(data.read(4))
            return UnencryptedMessage(message_id, data.read(message_data_length))
        
        return EncryptedMessage(auth_key_id, data.read(16), data.read())

    async def send(self, objects: TL | list[tuple[TL, CoreMessage]], session_id: int, originating_request: Optional[CoreMessage] = None):
        payload = await self.encrypt(
            objects, session_id, 
            originating_request=originating_request.message_id if originating_request else None
        )
        await self.conn.send(payload)

    async def handle_unencrypted_message(self, obj: TL):
        match obj._:
            case "req_pq_multi" | "req_pq":
                await self._process_req_pq(obj)
            case "req_DH_params":
                await self._process_req_dh_params(obj)
            case "set_client_DH_params":
                await self._process_set_client_dh_params(obj)
            case "msgs_ack":
                logger.debug(f"Received ACK for messages: {obj.msg_ids}")
            case _:
                raise RuntimeError(f"Unexpected unencrypted packet: {obj._}")

    async def _process_req_pq(self, obj: TL):
        p = generate_large_prime(31)
        q = generate_large_prime(31)
        if p > q: p, q = q, p

        self.auth_data = SimpleNamespace()
        self.auth_data.p, self.auth_data.q = p, q
        self.auth_data.server_nonce = int.from_bytes(secrets.token_bytes(16), byteorder="big")

        pq_bytes = (p * q).to_bytes(8, "big", signed=False)
        res_pq = TL.encode({
            "_": "resPQ",
            "nonce": obj.nonce,
            "server_nonce": self.auth_data.server_nonce,
            "pq": pq_bytes,
            "server_public_key_fingerprints": [self.server.fingerprint],
        })
        await self._send_unencrypted(res_pq)

    async def _process_req_dh_params(self, obj: TL):
        if not self.auth_data or self.auth_data.server_nonce != obj.server_nonce:
            raise ValueError("Authorization state nonce mismatch")

        key_aes_encrypted = rsa_pad_inverse(obj.encrypted_data, self.server.public_key, self.server.private_key).lstrip(b"\0")
        p_q_inner_data = TL.decode(BytesIO(key_aes_encrypted))

        self.auth_data.new_nonce = p_q_inner_data.new_nonce.to_bytes(32, "little", signed=False)
        
        self.auth_data.dh_prime = TELEGRAM_DH_PRIME
        g = TELEGRAM_DH_G

        self.auth_data.a = int.from_bytes(secrets.token_bytes(256), "big")
        g_a = pow(g, self.auth_data.a, self.auth_data.dh_prime).to_bytes(256, "big")

        answer = TL.encode({
            "_": "server_DH_inner_data",
            "nonce": p_q_inner_data.nonce,
            "server_nonce": self.auth_data.server_nonce,
            "g": g,
            "dh_prime": self.auth_data.dh_prime.to_bytes(256, "big", signed=False),
            "g_a": g_a,
            "server_time": int(time.time()),
        })

        server_nonce_bytes = self.auth_data.server_nonce.to_bytes(16, "little", signed=False)
        answer_with_hash = hashlib.sha1(answer).digest() + answer
        answer_with_hash += secrets.token_bytes(-len(answer_with_hash) % 16)

        self.auth_data.tmp_aes_key = hashlib.sha1(self.auth_data.new_nonce + server_nonce_bytes).digest() + hashlib.sha1(server_nonce_bytes + self.auth_data.new_nonce).digest()[:12]
        self.auth_data.tmp_aes_iv = hashlib.sha1(server_nonce_bytes + self.auth_data.new_nonce).digest()[12:] + hashlib.sha1(self.auth_data.new_nonce + self.auth_data.new_nonce).digest() + self.auth_data.new_nonce[:4]

        encrypted_answer = tgcrypto.ige256_encrypt(answer_with_hash, self.auth_data.tmp_aes_key, self.auth_data.tmp_aes_iv)
        server_dh_params_ok = TL.encode({
            "_": "server_DH_params_ok",
            "nonce": p_q_inner_data.nonce,
            "server_nonce": p_q_inner_data.server_nonce,
            "encrypted_answer": encrypted_answer,
        })
        await self._send_unencrypted(server_dh_params_ok)

    async def _process_set_client_dh_params(self, obj: TL):
        if not self.auth_data or not hasattr(self.auth_data, "tmp_aes_key"):
            raise ValueError("Invalid DH step state")

        decrypted_params = tgcrypto.ige256_decrypt(obj.encrypted_data, self.auth_data.tmp_aes_key, self.auth_data.tmp_aes_iv)
        client_DH_inner_data = TL.decode(BytesIO(decrypted_params[20:]))

        if not hmac.compare_digest(hashlib.sha1(TL.encode(client_DH_inner_data)).digest(), decrypted_params[:20]):
            raise ValueError("DH packet signature hash mismatch!")

        self.auth_data.auth_key = pow(int.from_bytes(client_DH_inner_data.g_b, "big", signed=False), self.auth_data.a, self.auth_data.dh_prime).to_bytes(256, "big", signed=False)
        
        auth_key_digest = hashlib.sha1(self.auth_data.auth_key).digest()
        dh_gen_ok = TL.encode({
            "_": "dh_gen_ok",
            "nonce": client_DH_inner_data.nonce,
            "server_nonce": self.auth_data.server_nonce,
            "new_nonce_hash1": int.from_bytes(hashlib.sha1(self.auth_data.new_nonce + bytes([1]) + auth_key_digest[:8]).digest()[-16:], "little", signed=False),
        })
        await self._send_unencrypted(dh_gen_ok)

        self.auth_data.auth_key_id = read_int(auth_key_digest[-8:])
        await self.server.register_auth_key(self.auth_data.auth_key_id, self.auth_data.auth_key, self.auth_data)
        logger.info(f"Key exchange completed. New auth_key_id: {self.auth_data.auth_key_id}")

    async def _send_unencrypted(self, payload: bytes):
        await self.conn.send(bytes(8) + Int64.serialize(self.msg_id(in_reply=True)) + Int32.serialize(len(payload)) + payload)

    async def worker(self):
        self.conn = await self.conn.init()
        while True:
            message = await self.read_message()
            msg_id = message.message_id if isinstance(message, UnencryptedMessage) else None

            if isinstance(message, EncryptedMessage):
                decrypted = await self.decrypt(message)
                msg_id = decrypted.message_id
                
                if msg_id in self.seen_msg_ids: continue
                self.seen_msg_ids.add(msg_id)
                
                self.last_session_id = decrypted.session_id

                try:
                    core_message = decrypted.to_core_message(TL)
                except InvalidConstructor as e:
                    await self.reply_invalid_constructor(e, decrypted)
                    continue

                if self.is_content_related(cast(TL, core_message.obj)):
                    self._incoming_content_related_msgs += 1
                
                await self.propagate(core_message, decrypted.session_id)

            elif isinstance(message, UnencryptedMessage):
                if msg_id in self.seen_msg_ids: continue
                self.seen_msg_ids.add(msg_id)
                await self.handle_unencrypted_message(TL.decode(BytesIO(message.message_data)))

    async def encrypt(self, objects: TL | list[tuple[TL, CoreMessage]], session_id: int, originating_request: Optional[int] = None) -> bytes:
        if not self.auth_data or not getattr(self.auth_data, 'auth_key', None):
            raise RuntimeError("Encryption without agreed auth_key")

        if isinstance(objects, TL):
            final_obj = objects
            serialized = TL.encode(objects)
            msg_id = self.msg_id(in_reply=True) if self.is_content_related(objects) else (originating_request + 1 if originating_request else self.msg_id(False))
            seq_no = self.get_outgoing_seq_no(objects)
        else:
            container = {"_": "msg_container", "messages": []}
            for obj, core_message in objects:
                serialized = TL.encode(obj)
                msg_id = self.msg_id(in_reply=True) if self.is_content_related(obj) else core_message.message_id + 1
                seq_no = self.get_outgoing_seq_no(obj)
                container["messages"].append(Int64.serialize(msg_id) + Int32.serialize(seq_no) + Int32.serialize(len(serialized)) + serialized)
            final_obj = TL.from_dict(container)
            serialized = TL.encode(final_obj)

        data = Int64.serialize(self.server.salt) + Int64.serialize(session_id) + Int64.serialize(self.msg_id(in_reply=True)) + self.get_outgoing_seq_no(final_obj).to_bytes(4, "little") + len(serialized).to_bytes(4, "little") + serialized
        padding = os.urandom(-(len(data) + 12) % 16 + 12)
        
        msg_key = hashlib.sha256(self.auth_data.auth_key[96:128] + data + padding).digest()[8:24]
        aes_key, aes_iv = kdf(self.auth_data.auth_key, msg_key, False)
        return Int64.serialize(self.auth_data.auth_key_id) + msg_key + tgcrypto.ige256_encrypt(data + padding, aes_key, aes_iv)

    async def decrypt(self, message: EncryptedMessage) -> DecryptedMessage:
        if not self.auth_data:
            got = await self.server.get_auth_key(message.auth_key_id)
            if not got: raise RuntimeError("Session key not found")
            self.auth_data = got[1]

        aes_key, aes_iv = kdf(self.auth_data.auth_key, message.msg_key, True)
        decrypted = BytesIO(tgcrypto.ige256_decrypt(message.encrypted_data, aes_key, aes_iv))
        return DecryptedMessage(decrypted.read(8), read_int(decrypted.read(8)), read_int(decrypted.read(8)), read_int(decrypted.read(4)), decrypted.read(read_int(decrypted.read(4))), decrypted.read())

    async def reply_invalid_constructor(self, e: InvalidConstructor, decrypted: DecryptedMessage):
        formatted = f"{e.cid:x}".zfill(8).upper()
        await self.send(TL.from_dict({"_": "rpc_result", "req_msg_id": decrypted.message_id, "result": {"_": "rpc_error", "error_code": 400, "error_message": f"INPUT_CONSTRUCTOR_INVALID_{formatted}"}}), session_id=decrypted.session_id)

    @staticmethod
    def is_content_related(obj: TL) -> bool:
        return obj._ not in ["ping", "pong", "http_wait", "msgs_ack", "msg_container"]

    def msg_id(self, in_reply: bool) -> int:
        now = int(time.time())
        self._msg_id_offset = (self._msg_id_offset + 4) if now == self._msg_id_last_time else 0
        self._msg_id_last_time = now
        return (now * 2**32) + self._msg_id_offset + (1 if in_reply else 3)

    def get_outgoing_seq_no(self, obj: TL) -> int:
        ret = self._outgoing_content_related_msgs * 2
        if self.is_content_related(obj):
            self._outgoing_content_related_msgs += 1
            ret += 1
        return ret

    async def propagate(self, request: CoreMessage, session_id: int):
        if request.obj._ == "msg_container":
            results = []
            for msg in request.obj.messages:
                res = await self._dispatch_single(msg, session_id)
                if res: results.append((res, msg))
            if results: await self.send(results, session_id)
        else:
            res = await self._dispatch_single(request, session_id)
            if res: await self.send(res, session_id, originating_request=request)

    async def _dispatch_single(self, msg: CoreMessage, session_id: int) -> Optional[TL]:
        res = await self.server._dispatch(self, msg, session_id)
        if res is None:
            return TL.from_dict({"_": "rpc_error", "error_code": 501, "error_message": "Not implemented"})
        if res is False:
            return None
        if isinstance(res, dict):
            res = TL.from_dict(res)
        if res._ not in ("ping", "pong", "rpc_result"):
            res = TL.from_dict({"_": "rpc_result", "req_msg_id": msg.message_id, "result": res})
        return res