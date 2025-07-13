from flask import Flask, render_template, request, redirect, url_for, session
import requests
from IBI_Scheme import Prove_commit, Prove
from ecp import ECp
from ecp2 import ECp2
from big import from_bytes as big_from_bytes
import sys
import time
sys.path.append('/Users/soxinyuan/core/python')
sys.path.append('/Users/soxinyuan/core/python/bls12381')

app = Flask(__name__)
app.secret_key = 'your_secret_key'
SERVER_URL = "http://172.20.10.3:5000"

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        identity = request.form['identity']
        try:
            res = requests.post(f"{SERVER_URL}/keygen", json={"identity": identity})
            data = res.json()
            s_hex = data['s']
            r_hex = data['r']
            return render_template("register.html", message=f"✅ Registered: {identity}", s_val=s_hex, r_val=r_hex, identity_val=identity)
        except Exception as e:
            return render_template("register.html", message=f"Registration failed: {e}")
    return render_template("register.html")



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identity = request.form['identity'].strip()
        s_hex = request.form['s'].strip()
        r_hex = request.form['r'].strip()
        try:
            s = ECp()
            s.fromBytes(bytes.fromhex(s_hex))
            r = big_from_bytes(bytes.fromhex(r_hex))
            usk = (s, r)

            v_res = requests.post(f"{SERVER_URL}/keygen", json={"identity": identity})
            v_res.raise_for_status()
            v_hex = v_res.json()['v']
            v = ECp2()
            v.fromBytes(bytes.fromhex(v_hex))

            #time 
            prove_commit_start = time.time()
            print(f"[CLIENT] Proving commitment for identity: {identity}")

            mpk = (None, None, None, v, None)
            (S, R), r_tilde = Prove_commit(mpk, usk)

            prove_commit_end = time.time()
            print(f"[CLIENT] Prove_commit took {prove_commit_end - prove_commit_start:.6f} seconds for identity: {identity}")

            S_hex = S.toBytes(True).hex()
            R_hex = R.toBytes(True).hex()

            commit_res = requests.post(f"{SERVER_URL}/commit", json={"identity": identity, "S": S_hex, "R": R_hex})
            c_hex = commit_res.json()['c']
            c = big_from_bytes(bytes.fromhex(c_hex))

            #time
            prove_start = time.time()
            print(f"[CLIENT] Proving for identity: {identity}")
            
            r_hat = Prove(usk, r_tilde, c)
            r_hat_hex = r_hat.to_bytes((r_hat.bit_length() + 7) // 8, 'big').hex()

            prove_end = time.time()
            print(f"[CLIENT] Prove took {prove_end - prove_start:.6f} seconds for identity: {identity}")

            payload = {
                "identity": identity,
                "s": s_hex,
                "R": R_hex,
                "r_hat": r_hat_hex,
                "c": c_hex
            }
            verify_res = requests.post(f"{SERVER_URL}/verify", json=payload)
            result = verify_res.json().get("result", "❌ No result from server")

            if "Verified" in result:
                session['identity'] = identity
                return redirect(url_for('dashboard'))
            else:
                return render_template("login.html", message="❌ Verification failed.")
        except Exception as e:
            return render_template("login.html", message=f"Verification failed: {e}")
    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'identity' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html", identity=session['identity'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
