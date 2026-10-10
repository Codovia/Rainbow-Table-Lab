"""Rainbow Table Attack — Virtual Lab (Fullstack)"""

import hashlib
import random
import time
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Algorithm parameters
CHARSET = "abcdefghijklmnopqrstuvwxyz"
PW_LEN = 4
TOTAL_SPACE = len(CHARSET) ** PW_LEN  # 456,976 possible passwords (26^4)

NUM_TABLES = 3  # Multiple tables with distinct reduction functions close coverage gaps
CHAINS_PER_TABLE = TOTAL_SPACE
CHAIN_LENGTH = 20
BASE_SEED = 3  # Fixed seed ensures reproducible tables

# Short chains reduce collisions/merges (birthday paradox in small keyspaces),
# while multiple independent reduction functions achieve high coverage (~99%).

# In-memory store for generated tables and build metrics
STATE = {"tables": [], "built": False, "build_stats": None}


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def index_to_pw(index: int) -> str:
    """Map an integer 0..456975 to a unique 4-letter password. This is how
    we enumerate 'all possible combinations' systematically, instead of
    relying on repeated random guesses that could pick the same word twice."""
    chars = []
    n = index
    for _ in range(PW_LEN):
        n, rem = divmod(n, len(CHARSET))
        chars.append(CHARSET[rem])
    return "".join(chars)


def reduce_fn(hash_hex: str, position: int, table_idx: int) -> str:
    """Reduction function: hash -> password candidate. Varies by chain
    position AND by table index, so different tables genuinely cover
    different parts of the password space."""
    seed = int(hash_hex, 16) + position + table_idx * 1000003
    return index_to_pw(seed % TOTAL_SPACE)


def build_chain(start: str, length: int, table_idx: int) -> str:
    cur = start
    h = md5(cur)
    for pos in range(length):
        cur = reduce_fn(h, pos, table_idx)
        h = md5(cur)
    return h


def build_one_table(num_chains: int, chain_length: int, table_idx: int, seed: int):
    """Builds one rainbow table using UNIQUE starting passwords — sampled
    without replacement from the full combination space, so no starting
    password is ever picked twice within a table."""
    rng = random.Random(seed)
    start_indices = rng.sample(range(TOTAL_SPACE), num_chains)
    table = {}
    collisions = 0
    for idx in start_indices:
        start = index_to_pw(idx)
        end = build_chain(start, chain_length, table_idx)
        if end in table:
            collisions += 1
        else:
            table[end] = start
    return table, collisions


def crack_password(target_hash: str):
    """
    Searches all built tables for target_hash. Returns:
      recovered   - the plaintext password, or None
      search_log  - one summary entry PER TABLE with detailed events
                    (endpoint matches, false alarms) for transparency
      regen_trace - the FULL step-by-step walk of the winning chain
    """
    search_log = []
    regen_trace = []
    recovered = None

    for t_idx, table in enumerate(STATE["tables"]):
        positions_checked = 0
        found_in_table = False
        events = []  # Track each endpoint match for transparency

        # Check candidate positions backwards from chain endpoint.
        # A false alarm at one position does not preclude a match at another.
        for guess_pos in range(CHAIN_LENGTH - 1, -1, -1):
            cur = target_hash
            for pos in range(guess_pos, CHAIN_LENGTH):
                cur = md5(reduce_fn(cur, pos, t_idx))
            positions_checked += 1
            if cur not in table:
                continue

            # Endpoint match: regenerate chain from start password to locate plaintext
            start_pw = table[cur]
            endpoint_hash = cur
            full_regen = []
            rcur, h = start_pw, md5(start_pw)
            match_pw = None
            for pos in range(CHAIN_LENGTH):
                full_regen.append({"step": pos, "password": rcur, "hash": h})
                if h == target_hash:
                    match_pw = rcur
                    break
                rcur = reduce_fn(h, pos, t_idx)
                h = md5(rcur)

            if match_pw:
                recovered = match_pw
                regen_trace = full_regen  # Full trace, no trimming
                found_in_table = True
                events.append({
                    "type": "match",
                    "position": guess_pos,
                    "chain_start": start_pw,
                    "endpoint": endpoint_hash[:16],
                    "matched_step": len(full_regen) - 1,
                })
                break

            # False alarm: endpoint matched via chain merge, but target hash was not in chain
            events.append({
                "type": "false_alarm",
                "position": guess_pos,
                "chain_start": start_pw,
                "endpoint": endpoint_hash[:16],
            })

        search_log.append({
            "table": t_idx + 1,
            "positions_checked": positions_checked,
            "hit": found_in_table,
            "false_alarms": len([e for e in events if e["type"] == "false_alarm"]),
            "events": events,
        })

        if found_in_table:
            break

    return recovered, search_log, regen_trace


# Routes

@app.route("/")
def index():
    return render_template("index.html", total_space=f"{TOTAL_SPACE:,}",
                            num_tables=NUM_TABLES, chains=CHAINS_PER_TABLE,
                            chain_len=CHAIN_LENGTH)


@app.route("/api/build", methods=["POST"])
def api_build():
    t0 = time.time()
    tables = []
    total_collisions = 0
    for t in range(NUM_TABLES):
        table, collisions = build_one_table(CHAINS_PER_TABLE, CHAIN_LENGTH, t, BASE_SEED + t * 7919)
        tables.append(table)
        total_collisions += collisions
    build_ms = int((time.time() - t0) * 1000)

    STATE["tables"] = tables
    STATE["built"] = True
    total_stored = sum(len(t) for t in tables)
    STATE["build_stats"] = {
        "tables_built": NUM_TABLES,
        "total_stored": total_stored,
        "collisions_dropped": total_collisions,
        "build_ms": build_ms,
        "total_space": TOTAL_SPACE,
        "chain_length": CHAIN_LENGTH,
    }
    return jsonify(STATE["build_stats"])


@app.route("/api/hash", methods=["POST"])
def api_hash():
    data = request.get_json(force=True)
    pw = (data.get("password") or "").lower()
    if len(pw) != PW_LEN or any(c not in CHARSET for c in pw):
        return jsonify({"error": f"Enter exactly {PW_LEN} lowercase letters (a-z)."}), 400
    return jsonify({"password": pw, "hash": md5(pw)})


@app.route("/api/crack", methods=["POST"])
def api_crack():
    if not STATE["built"]:
        return jsonify({"error": "Build the table first."}), 400
    data = request.get_json(force=True)
    target_hash = data.get("hash", "")
    if len(target_hash) != 32:
        return jsonify({"error": "Invalid hash."}), 400

    t0 = time.time()
    recovered, search_log, regen_trace = crack_password(target_hash)
    crack_ms = round((time.time() - t0) * 1000, 1)

    verified = (recovered is not None) and (md5(recovered) == target_hash)
    return jsonify({
        "recovered": recovered if verified else None,
        "verified": verified,
        "target_hash": target_hash,
        "crack_ms": crack_ms,
        "search_log": search_log,
        "regen_trace": regen_trace,
    })


@app.route("/api/sample", methods=["GET"])
def api_sample():
    """Returns a password that is guaranteed to be crackable (a real
    starting password from one of the built tables) - for a reliable demo."""
    if not STATE["built"]:
        return jsonify({"error": "Build the table first."}), 400
    table = random.choice(STATE["tables"])
    start_pw = random.choice(list(table.values()))
    return jsonify({"password": start_pw})


@app.route("/api/combinations")
def api_combinations():
    """Illustrates the full combination space: total count + a small,
    non-repeating sample of what it actually contains."""
    rng = random.Random(1)
    sample_indices = rng.sample(range(TOTAL_SPACE), 8)
    sample = sorted(index_to_pw(i) for i in sample_indices)
    return jsonify({"total": TOTAL_SPACE, "sample": sample})


if __name__ == "__main__":
    app.run(debug=True)
