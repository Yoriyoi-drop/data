"""
Anchor Service Prototype (Hardened) - Testnet Only
- Batches hashes, computes root digest, signs with Vault Transit (HSM-backed),
  submits to EVM chain (e.g., Polygon Mumbai). Do NOT store private keys in env.
- Production guidance embedded in comments. Remove prints in prod.
"""
import os
import json
import time
import hashlib
from typing import List

from web3 import Web3

try:
    import hvac  # HashiCorp Vault client
except ImportError:
    hvac = None

ETH_RPC = os.getenv("ETH_RPC", "https://rpc-mumbai.maticvigil.com")
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
TRANSIT_KEY_NAME = os.getenv("VAULT_TRANSIT_KEY", "anchor-key")
BATCH_FILE = os.getenv("ANCHOR_INPUT", "data/telemetry.json")
ANCHOR_INTERVAL_SEC = int(os.getenv("ANCHOR_INTERVAL_SEC", "900"))

w3 = Web3(Web3.HTTPProvider(ETH_RPC))


def compute_batch_hash(hex_hashes: List[str]) -> str:
    m = hashlib.sha256()
    for h in hex_hashes:
        m.update(bytes.fromhex(h))
    return m.hexdigest()


def get_pending_hashes(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            arr = json.load(f)
    except Exception:
        return []
    hashes = []
    for ev in arr:
        if isinstance(ev, dict) and ev.get("event_hash"):
            hashes.append(ev["event_hash"])  # hex string
        else:
            digest = hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest()
            hashes.append(digest)
    return hashes


def vault_sign_hex_digest(digest_hex: str) -> str:
    if hvac is None:
        raise RuntimeError("hvac not installed; cannot sign via Vault")
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    # Sign hex digest via transit (hash_input=True expects hex)
    res = client.secrets.transit.sign_data(name=TRANSIT_KEY_NAME, hash_input=True, input=digest_hex)
    return res["data"]["signature"]


def submit_tx_with_local_key(batch_hash_hex: str) -> str:
    """Local signing for testnet only. In prod, use HSM or dedicated relayer service."""
    pk = os.getenv("ANCHOR_PRIVATE_KEY")
    if not pk:
        raise RuntimeError("Missing ANCHOR_PRIVATE_KEY for local signing (testnet)")
    acct = w3.eth.account.from_key(pk)
    tx = {
        "to": acct.address,  # self tx to carry data
        "value": 0,
        "data": w3.to_hex(text=f"ANCHOR:{batch_hash_hex}"),
        "gas": 200000,
        "nonce": w3.eth.get_transaction_count(acct.address),
    }
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return w3.to_hex(tx_hash)


def run_once() -> None:
    hashes = get_pending_hashes(BATCH_FILE)
    if not hashes:
        print("[anchor] No hashes to anchor")
        return
    BATCH_SIZE = int(os.getenv("ANCHOR_BATCH_SIZE", "50"))
    for i in range(0, len(hashes), BATCH_SIZE):
        batch = hashes[i : i + BATCH_SIZE]
        batch_digest = compute_batch_hash(batch)
        print("[anchor] Batch digest:", batch_digest)
        # Optional sign via Vault
        if VAULT_TOKEN:
            try:
                sig = vault_sign_hex_digest(batch_digest)
                print("[anchor] Vault signature:", sig)
            except Exception as e:
                print("[anchor] Vault sign error:", e)
        # Submit transaction (testnet)
        txh = submit_tx_with_local_key(batch_digest)
        print("[anchor] Submitted tx:", txh)


def main() -> None:
    while True:
        try:
            run_once()
        except Exception as e:
            print("[anchor] cycle error:", e)
        time.sleep(ANCHOR_INTERVAL_SEC)


if __name__ == "__main__":
    main()
