import sys
import time
sys.path.append('/home/kali/Desktop/core/python')
sys.path.append('/home/kali/Desktop/core/python/bls12381')

from flask import Flask, request, jsonify
from IBI_Scheme import Setup, KeyGen, Verify, Verify_challenge
from ecp import ECp
from ecp2 import ECp2
from big import from_bytes as big_from_bytes

app = Flask(__name__)

print("[SERVER] Starting IBI Scheme Server...")
setup_start = time.time()

mpk, msk = Setup()

setup_end = time.time()
print(f"[SERVER] Setup completed in {setup_end - setup_start:.6f} seconds")

@app.route('/keygen', methods=['POST'])
def keygen():
    #time
    start = time.time()  


    data = request.get_json()
    identity = data.get('identity')
    try:
        usk = KeyGen(mpk, msk, identity)
        s, r = usk
        s_hex = s.toBytes(True).hex()
        r_hex = r.to_bytes((r.bit_length() + 7) // 8, 'big').hex()
        v_hex = mpk[3].toBytes(True).hex()

        end = time.time() 
        print(f"[SERVER] /keygen took {end - start:.6f} seconds for identity: {identity}")

        return jsonify({"s": s_hex, "r": r_hex, "v": v_hex})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/verify', methods=['POST'])
def verify():
    #time
    import time
    start = time.time()

    data = request.get_json()
    try:
        identity = data['identity']
        s_hex = data['s']
        R_hex = data['R']
        r_hat_hex = data['r_hat']
        c_hex = data['c']

        s = ECp()
        s.fromBytes(bytes.fromhex(s_hex))
        R = ECp2()
        R.fromBytes(bytes.fromhex(R_hex))
        r_hat = big_from_bytes(bytes.fromhex(r_hat_hex))
        c = big_from_bytes(bytes.fromhex(c_hex))

        commit = (s, R)
        valid = Verify(mpk, r_hat, commit, c, identity)
        result = "Verified" if valid else "Verification Failed"

        end = time.time() 
        print(f"[SERVER] /verify took {end - start:.6f} seconds")

        return jsonify({"result": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


challenges = {}

@app.route('/commit', methods=['POST'])
def commit():
    # time
    start = time.time()  


    data = request.get_json()
    print("/commit received:", data)  
    try:
        identity = data['identity']
        S_hex = data['S']
        R_hex = data['R']

        S = ECp()
        S.fromBytes(bytes.fromhex(S_hex))
        R = ECp2()
        R.fromBytes(bytes.fromhex(R_hex))

        commit_pair = (S, R)
        c = Verify_challenge()

        challenges[identity] = c
        c_hex = c.to_bytes((c.bit_length() + 7) // 8, 'big').hex()
        print(f"Challenge for {identity}: {c_hex}")  

        end = time.time()
        print(f"[SERVER] /commit took {end - start:.6f} seconds for identity: {identity}")

        return jsonify({"c": c_hex})

    except Exception as e:
        print("Error in /commit:", e)  
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='172.20.10.3', port=5000, debug=True)
