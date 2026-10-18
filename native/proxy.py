"""Trusted mitmproxy addon. Customer rules stay declarative in the policy service."""
import asyncio
from http.client import HTTPConnection
import json
import socket
from pathlib import Path
from mitmproxy import ctx, http

class UnixHTTP(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(ctx.options.verklikker_socket)

def call(path, value):
    c = UnixHTTP('policy', timeout=10)
    try:
        c.request('POST', path, json.dumps(value), {'Content-Type': 'application/json'})
        response = c.getresponse()
        if response.status != 200:
            raise RuntimeError('Policy unavailable')
        return json.loads(response.read(2 * 1024 * 1024))
    finally:
        c.close()

class PolicyAddon:
    def load(self, loader):
        loader.add_option('verklikker_socket', str, '', 'Private policy socket')
        loader.add_option('verklikker_ready', str, '', 'Readiness file')

    async def running(self):
        for _ in range(200):
            for server in ctx.master.addons.get('proxyserver').servers:
                for address in server.listen_addrs:
                    Path(ctx.options.verklikker_ready).write_text(json.dumps({'address': f'{address[0]}:{address[1]}'}))
                    return
            await asyncio.sleep(0.05)
        raise RuntimeError('Proxy listener unavailable')

    async def server_connect(self, data):
        try:
            hostname, port = data.server.address
            result = await asyncio.to_thread(call, '/proxy-resolve', {'host': hostname, 'port': port})
            if result['action'] != 'allow':
                data.server.error = 'Policy denied upstream connection'
                return
            # Pin the exact checked address. Preserve SNI/certificate verification for the requested host.
            data.server.sni = data.server.sni or hostname
            data.server.address = (result['ip'], port)
        except Exception:
            data.server.error = 'Policy evaluation failed'

    async def request(self, flow: http.HTTPFlow):
        try:
            result = await asyncio.to_thread(call, '/proxy-resolve', {'host': flow.request.host, 'port': flow.request.port})
            if result['action'] == 'mock':
                response = result['response']
                flow.response = http.Response.make(response['status'], response['body'].encode(), response['headers'])
            elif result['action'] != 'allow':
                flow.response = http.Response.make(403, b'Blocked by investigation policy')
        except Exception:
            flow.response = http.Response.make(502, b'Policy service unavailable')

    async def response(self, flow: http.HTTPFlow):
        await asyncio.to_thread(call, '/proxy-event', {'method': flow.request.method, 'url': flow.request.pretty_url, 'status': flow.response.status_code, 'requestBytes': len(flow.request.raw_content or b''), 'responseBytes': len(flow.response.raw_content or b'')})

addons = [PolicyAddon()]
