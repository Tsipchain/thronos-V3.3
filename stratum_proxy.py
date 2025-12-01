#!/usr/bin/env python3
"""
Thronos Stratum Proxy
~~~~~~~~~~~~~~~~~~~~~
Bridges standard Stratum miners (ASIC, USB Erupters, cgminer) to the Thronos HTTP API.

It emulates a Stratum pool server on port 3333:
1. Accepts connections from miners.
2. Fetches current block info from Thronos HTTP API.
3. Converts it to Stratum jobs.
4. Sends jobs to miners.
5. Receives shares/solutions.
6. Submits valid solutions back to Thronos HTTP API.
"""

import asyncio
import json
import time
import hashlib
import aiohttp
import binascii
import struct

# Configuration
STRATUM_HOST = "0.0.0.0"
STRATUM_PORT = 3333
THRONOS_API_URL = "https://thrchain.up.railway.app"  # Update with your server URL
THR_ADDRESS = "THR_POOL_ADDRESS"  # Fallback pool address (if miner address is not provided)

# Global state
current_job_id = 0
current_job_data = {}
connected_miners = []

async def get_chain_info():
    """Fetches the latest block hash and info from Thronos API."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{THRONOS_API_URL}/last_block_hash") as resp:
                if resp.status == 200:
                    return await resp.json()
    except Exception as e:
        print(f"Error fetching chain info: {e}")
    return None

async def submit_work(nonce, pow_hash, prev_hash, thr_address):
    """Submits valid work to Thronos API."""
    # Use miner's THR address for rewards; fallback to pool address if None.
    payload = {
        "thr_address": thr_address or THR_ADDRESS,
        "nonce": nonce,
        "pow_hash": pow_hash,
        "prev_hash": prev_hash
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{THRONOS_API_URL}/submit_block", json=payload) as resp:
                result = await resp.text()
                print(f"Share submitted: {resp.status} - {result}")
                return resp.status == 200
    except Exception as e:
        print(f"Error submitting work: {e}")
        return False

def create_stratum_job(prev_hash_hex):
    """Creates a Stratum job from the previous block hash."""
    global current_job_id
    current_job_id += 1
    
    # Stratum fields (simplified for this bridge)
    # prev_hash as big-endian or little-endian may vary; using hex string directly.
    merkle_root = "0" * 64  # placeholder Merkle root (no transactions)
    version = "20000000"    # Version 2
    nbits = "1d00ffff"      # Difficulty bits (simplified)
    ntime = hex(int(time.time()))[2:]
    clean_jobs = True
    
    job = [
        hex(current_job_id)[2:],  # Job ID
        prev_hash_hex,            # Previous Hash (hex)
        merkle_root,              # Merkle Root (placeholder)
        version,                  # Version
        nbits,                    # Bits (difficulty)
        ntime,                    # Time
        clean_jobs                # Clean Jobs flag
    ]
    
    return job

async def stratum_server(reader, writer):
    """Handles a single miner connection (per-worker state is local to this coroutine)."""
    addr = writer.get_extra_info('peername')
    print(f"New miner connected: {addr}")
    connected_miners.append(writer)
    
    # Session state for this connection
    extranonce1 = binascii.hexlify(struct.pack('>I', int(time.time()))).decode()
    extranonce2_size = 4
    difficulty = 1  # Start with diff 1
    thr_address = None  # Miner THR address (parsed from worker name)
    
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
                
            elif method == 'mining.authorize':
                # Parse THR address from worker name (format: "THR<address>.worker")
                worker = params[0] if params else None
                if worker:
                    thr_address = worker.split('.')[0]  # e.g., "THR1764439422895"
                    print(f"Set thr_address to {thr_address} for worker {worker}")
                
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
                
                # Use previously parsed thr_address or fallback to worker's address
                if thr_address is None and worker:
                    thr_address = worker.split('.')[0]
                
                # Retrieve previous block hash for this job
                prev_hash = current_job_data.get('prev_hash', "0"*64)
                # Calculate proof-of-work hash: SHA256(prev_hash + thr_address + nonce)
                check_data = (prev_hash + thr_address).encode() + str(nonce).encode()
                check_hash = hashlib.sha256(check_data).hexdigest()

                # Submit the work with computed hash to Thronos API
                await submit_work(nonce, check_hash, prev_hash, thr_address)
                
                # Respond to miner that share was accepted (simplified)
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
        await writer.wait_closed()

async def job_updater():
    """Periodically checks for new blocks and pushes jobs to all connected miners."""
    last_hash = None
    while True:
        info = await get_chain_info()
        if info:
            current_hash = info.get("last_hash")
            if current_hash != last_hash:
                print(f"New block detected: {current_hash}")
                last_hash = current_hash
                
                # Create and store new Stratum job
                job_params = create_stratum_job(current_hash)
                current_job_data['job'] = job_params
                current_job_data['prev_hash'] = current_hash
                
                # Notify all miners of new job
                notify_msg = {
                    "params": job_params,
                    "method": "mining.notify",
                    "id": None
                }
                json_msg = json.dumps(notify_msg) + '\n'
                
                for miner in connected_miners:
                    try:
                        miner.write(json_msg.encode())
                        await miner.drain()
                    except:
                        # Miner may have disconnected
                        pass
                        
        await asyncio.sleep(10)  # Check every 10 seconds

async def main():
    print(f"Starting Thronos Stratum Proxy on port {STRATUM_PORT}...")
    server = await asyncio.start_server(stratum_server, STRATUM_HOST, STRATUM_PORT)
    
    # Start background job updater
    asyncio.create_task(job_updater())
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down proxy...")
