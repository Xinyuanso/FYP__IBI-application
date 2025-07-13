import sys
import random
import hashlib

# sys.path.append('/Users/soxinyuan/core/python')
# # MIRACL Core BLS12381 
# sys.path.append('/Users/soxinyuan/core/python/bls12381')

sys.path.append('/home/kali/Desktop/core/python')
# MIRACL Core BLS12381 
sys.path.append('/home/kali/Desktop/core/python/bls12381')


from ecp import ECp, generator as g1_gen
from ecp2 import ECp2, generator as g2_gen
import pair
import big
import curve

p = curve.r

# --- Hash function for IDs ---
def H(ID):
    h = hashlib.shake_256()
    h.update(ID.encode('utf-8'))
    digest = h.digest(curve.EFS)
    return big.from_bytes(digest) % p


# --- System Setup ---
def Setup():

    g1 = g1_gen()
    g2 = g2_gen() 

    x = big.rand(p)
    y = big.rand(p)

    pairing_e = pair.e(g2, g1)

    u = x * g2
    v = y * g2

    mpk = (g1, g2, u, v, pairing_e)
    msk = (x, y)
    return mpk, msk

# --- User Key Generation ---
def KeyGen(mpk, msk, ID):

    x, y = msk
    g1, g2, u, v, pairing_e = mpk

    h = H(ID)
    r = big.rand(p)

    while True: 
        denom = x + h + y * r
        if denom != 0 % p:
            break

    inv = pow(denom, -1, p)

    s = inv * g1 
    usk = (s, r)
    return usk

def Prove_commit(mpk, usk):
    g1, g2, u, v, pairing_e = mpk 
    s, r = usk 

    r_tidle = big.rand(p)
    big_r = r_tidle * v
    commit = (s , big_r)

    return commit , r_tidle
    

# --- Proving ---
def Prove( usk, r_tilde, c):
    
    s, r = usk 

    r_hat = r_tilde + (c * r)
    return r_hat
    

def Verify_challenge():

    c = big.rand(p)
    return c

# --- Verifying ---
def Verify(mpk, r_hat, commit, c,ID):

    g1, g2, u, v, pairing_e = mpk 
    s , big_r = commit 

    h = H(ID)
    x = h * g2      

    # Compute v^r' · R^{-1}
    t = r_hat * v          # v^r'
    invR = -big_r # R^{-1}
    t.add(invR)                # T = v^r' * R^{-1}

    # Raise (v^r' R^{-1}) to 1/c
    c_inv = pow(c, -1, curve.r)
    t2 = c_inv * t             # (v^r' R^{-1})^{1/c}

    # Multiply everything: u · g2^h · T2
    x.add(u)                   # X = g2^h + u
    x. add(t2)        

    pairing_e2 = pair.e(x, s)


    if pairing_e2 == pairing_e:
        return True
    else:
        return False
   

 
# --- Demo Run ---
if __name__ == '__main__':
    ID = "1211100165@student.mmu.edu.my"

    # System setup
    print("▶ Setting up system...")
    mpk, msk = Setup()
    g1, g2, u, v, pairing_e = mpk

    #  KeyGen: user obtains (s, r)
    print(f"▶ Generating secret key for: {ID}")
    usk = KeyGen(mpk, msk, ID)

    #  Prover’s first move: commitment
    (S, R), r_tilde = Prove_commit(mpk, usk)
    print("▶ Commitment (S,R):")
    print("   S =", S)
    print("   R =", R)

    #  Verifier’s challenge
    c = Verify_challenge()
    print("▶ Challenge c =", c)

    #  Prover’s response
    r_hat = Prove(usk, r_tilde, c)
    print("▶ Response r_hat =", r_hat)

    # Final verify
    valid = Verify(mpk, r_hat, (S, R), c, ID)
    if valid:
        print(" Identity verified successfully.")
    else:
        print(" Verification failed.")
