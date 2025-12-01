#!/usr/bin/env python3
"""
Thronos Stratum Proxy
~~~~~~~~~~~~~~~~~~~~~
Bridges standard Stratum miners (ASIC, USB Erupters, cgminer) to the Thronos HTTP API.

It emulates a Stratum pool server on port (default 3333).
"""

import asyncio
import json
import time
import hashlib
import aiohttp
import binascii
import struct

STRATUM_PORT = 3333
THRONOS_API_URL = "https://thrchain.up.railway.app/api"  # Example Thronos API endpoint

# Use THR_ADDRESS as the central proxy wallet address
THR_ADDRESS = "THR1764434930480" # Address to credit rewards to (pool wallet)

connected_miners = []
current_job_data = {}
current_job_id = 0

async def get_chain_info():
    """Fetch the current chain/head info from Thronos API."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{THRONOS_API_URL}/current_head") as resp:
                data = await resp.json()
                return data
    except Exception as e:
        print(f"Error fetching chain info: {e}")
    return None

async def submit_work(nonce, pow_hash, prev_hash):
    """Submits valid work to Thronos API."""
    payload = {
        "thr_address": THR_ADDRESS,
        "nonce": nonce,
        "pow_hash": pow_hash,
        "prev_hash": prev_hash
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{THRONOS_API_URL}/submit_block", json=payload) as resp:
                result = await resp.text()
                print(f"Submitted work: nonce={nonce}, pow_hash={pow_hash}, prev_hash={prev_hash}")
                print(f"API response: {result}")
    except Exception as e:
        print(f"Error submitting work: {e}")

async def handle_miner(reader, writer):
    """Handles RPC from downstream miners (ASIC, USB, cgminer, etc)."""
    addr = writer.get_extra_info('peername')
    print(f"New miner connected: {addr}")
    connected_miners.append(writer)

    # Session state for this miner
    extranonce1 = binascii.hexlify(struct.pack('>I', int(time.time()))).decode()
    extranonce2_size = 4
    difficulty = 1  # Start with diff 1

    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            message = data.decode().strip()
            if not message:
                continue

            print(f"Received from {addr}: {message}")

            try:
                req = json.loads(message)
            except json.JSONDecodeError:
                continue

            msg_id = req.get('id')
            method = req.get('method')
            params = req.get('params', [])

            response = None

            if method == 'mining.subscribe':
                # Respond with subscription details
                response = {
                    "id": msg_id,
                    "result": [
                        [ ["mining.set_difficulty", "1"], ["mining.notify", "1"] ],
                        extranonce1,
                        extranonce2_size
                    ],
                    "error": None
                }
                # Send difficulty
                diff_notify = {"params": [difficulty], "method": "mining.set_difficulty", "id": None}
                writer.write((json.dumps(diff_notify) + '\n').encode())
                # Send current job immediately if available
                if current_job_data.get('job'):
                    job_notify = {
                        "params": current_job_data['job'],
                        "method": "mining.notify",
                        "id": None
                    }
                    writer.write((json.dumps(job_notify) + '\n').encode())

            elif method == 'mining.authorize':
                # Accept any worker for now
                response = {
                    "id": msg_id,
                    "result": True,
                    "error": None
                }
                # Send difficulty
                diff_notify = {"params": [difficulty], "method": "mining.set_difficulty", "id": None}
                writer.write((json.dumps(diff_notify) + '\n').encode())
                # Send current job immediately if available
                if current_job_data.get('job'):
                    job_notify = {
                        "params": current_job_data['job'],
                        "method": "mining.notify",
                        "id": None
                    }
                    writer.write((json.dumps(job_notify) + '\n').encode())

            elif method == 'mining.submit':
                # params: worker_name, job_id, extranonce2, ntime, nonce
                worker, job_id, en2, ntime, nonce = params
                print(f"Work received from {worker}: nonce={nonce}")

                # Fetch prev_hash from current job data
                prev_hash = current_job_data.get('prev_hash', "0"*64)

                # Calculate hash locally for Thronos proof-of-work
                nonce_str = str(nonce).encode()
                data = (prev_hash + THR_ADDRESS).encode() + nonce_str
                pow_hash = hashlib.sha256(data).hexdigest()
                await submit_work(nonce, pow_hash, prev_hash)

                response = {
                    "id": msg_id,
                    "result": True,
                    "error": None
                }

            if response:
                writer.write((json.dumps(response) + '\n').encode())
                await writer.drain()

    except Exception as e:
        print(f"Connection error with {addr}: {e}")
    finally:
        print(f"Miner disconnected: {addr}")
        connected_miners.remove(writer)
        writer.close()

async def stratum_server(reader, writer):
    """Wrapper around handle_miner to serve each connection."""
    await handle_miner(reader, writer)

async def main():
    """Main event loop to manage server and jobs."""
    global current_job_data, current_job_id

    server = await asyncio.start_server(stratum_server, '0.0.0.0', STRATUM_PORT)
    print(f"Stratum Proxy listening on port {STRATUM_PORT}...")

    async with server:
        # Poll Thronos API for new blocks and notify miners
        last_height = None
        while True:
            head_info = await get_chain_info()
            if head_info:
                new_height = head_info.get('height')
                if new_height != last_height:
                    last_height = new_height
                    prev_hash = head_info.get('prev_hash')
                    if prev_hash:
                        # Create new job for miners
                        current_job_id += 1
                        prev_hash_hex = prev_hash
                        merkle_root = "0"*64
                        version = "20000000"
                        nbits = "1d00ffff"
                        ntime = hex(int(time.time()))[2:].zfill(8)

                        job_params = [
                            hex(current_job_id)[2:],
                            prev_hash_hex,
                            merkle_root,
                            version,
                            nbits,
                            ntime,
                            extranonce1  # from session; placeholder for simplicity
                        ]
                        current_job_data['job'] = job_params
                        current_job_data['prev_hash'] = prev_hash_hex

                        # Broadcast new job to all connected miners
                        job_notify = {
                            "params": job_params,
                            "method": "mining.notify",
                            "id": None
                        }
                        for m in connected_miners:
                            m.write((json.dumps(job_notify) + '\n').encode())
                            await m.drain()
                        print(f"New job broadcast: {job_params}")

            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down proxy...")
