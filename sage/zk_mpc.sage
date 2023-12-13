from sage.all import *
from Cryptodome.Hash import SHAKE128
import random
import math

B = 2
K = B * 8
K2 = 1 << K

m = 1 << 7
M = m >> 1
L = m / M
GAMMA = int(math.ceil(math.log2(2*M)))
D = 40 + GAMMA


assert(L * M == m)

R = Integers(K2)
RR = PolynomialRing(R, 'x')
RR2 = PolynomialRing(GF(2), 'x')
POLY = RR(RR2.irreducible_element(D))
PolyR = PolynomialRing(RR, 'y')

tester = SHAKE128.new()
shakes = [SHAKE128.new() for _ in range(3)]

P0_0_input = []
P1_0_input = []
P2_0_input = []


def long_division(a, b):
    assert(b != 0)
    x = a
    y = b
    q = 0
    while x.degree() >= y.degree():
        factor = x.leading_coefficient() * y.leading_coefficient()^(-1) * RR.monomial(x.degree() - y.degree())
        x -= factor * y
        q += factor
    r = x
    return q, r


def extended_euclid(a,b):
    r0 = a; r1 = b
    s0 = 1; s1 = 0
    t0 = 0; t1 = 1

    while r1 != 0:
        q, r = long_division(r0, r1)

        assert(r == r0 - q * r1)
        r0, r1 = r1, r
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    return r0, s0, t0

def inv_mod(a, mod, prime_power):
    if prime_power == 1:
        aa,bb = RR2(a), RR2(mod)
        _, inv_aa, _ = extended_euclid(aa,bb)
        return inv_aa
    else:
        # Rk = PolynomialRing(Integers(2^(prime_power)), 'x')
        Rk = RR # in the general case use prime_power, but we use 2^K here
        inv = inv_mod(a, mod, prime_power - 1)
        g = Rk(inv)
        f = a
        _, r = (g * f -1).quo_rem(mod)
        _, inv = (g - r * g).quo_rem(mod)
        return inv

def RR_inverse(x):
    inv = inv_mod(x, POLY, K)
    assert((x * inv).quo_rem(POLY)[1] == 1)
    return inv


def interpolation_points(num):
    assert(num <= 1 << (D+1))
    x = [RR(i.bits()) for i in srange(num)]
    return x

def lagrange_polys(x):
    var = PolyR.gen()
    l_polys = []
    for j in range(len(x)):
        poly = PolyR(1)
        for i in range(len(x)):
            if (i != j):
                inv = RR_inverse(x[j] - x[i])
                poly *= (var - x[i]) * inv
        l_polys.append(poly)
    print("Lagrange Polys done!")
    return l_polys


x_coord = interpolation_points(M + 1)
lagrange = lagrange_polys(x_coord)

def ring_from_shake(shake):
    buf = shake.read(int(B))
    return R(int.from_bytes(buf, byteorder='little'))

def ring_from_rand():
    buf = random.randbytes(B)
    return R(int.from_bytes(buf, byteorder='little'))

def init_shakes():
    global shakes
    for i in range(len(shakes)):
        r = random.randbytes(32)
        shakes[i] = SHAKE128.new()
        shakes[i].update(r)
    global tester
    r = random.randbytes(32)
    tester = SHAKE128.new()
    tester.update(r)

def share(input):
    global shakes
    rands = []
    for i in range(3):
        rands.append(ring_from_shake(shakes[i]))
    shares = []
    for i in range(3):
        shares.append(rands[i] - rands[i-1])
    shares[0] += input
    return shares

def open(shares):
    return sum(shares)


def mul(a, b):
    rands = []
    for i in range(3):
        rands.append(ring_from_shake(shakes[i]))
    zero = []
    shares = []
    for i in range(3):
        zero.append(rands[i] - rands[i-1])
        s = a[i] * b[i] + a[i] * b[i-1] + a[i-1] * b[i] + zero[i]
        shares.append(s)

    # We just proof P0 for now
    global P0_0_input, P1_0_input, P2_0_input
    a0 = lift(a[0], 0)
    a1 = lift(a[-1], -1)
    b0 = lift(b[0], 0)
    b1 = lift(b[-1], -1)
    r0 = lift(rands[0], 0)
    r1 = lift(rands[-1], -1)
    z0 = r0 - r1

    s0 = (a0 * b0 + a0 * b1 + a1 * b0 + z0).quo_rem(POLY)[1] # this is necessary for the checks later on, cannot use the shares and lift


    P0_0_input.append([a0, a1, b0, b1, z0, s0])
    P1_0_input.append([a0, RR(0), b0, RR(0), r0, s0])
    P2_0_input.append([RR(0), a1, RR(0), b1, -r1, RR(0)])
    return shares

def coin():
    shake = SHAKE128.new()
    for _ in range(math.ceil(32 / B)):
        shares = []
        for i in range(3):
            shares.append(ring_from_shake(shakes[i]))
        bytes = int(open(shares))
        shake.update(bytes.to_bytes(B, byteorder='little'))
    return shake

def poly_from_shake(shake):
    coeffs = []
    for _ in range(D):
        coeffs.append(ring_from_shake(shake))
    return RR(coeffs)

def poly_from_rand():
    coeffs = []
    for _ in range(D):
        coeffs.append(ring_from_rand())
    return RR(coeffs)


def lift(x, id):
    coeffs = []
    coeffs.append(x)
    for _ in range(D-1):
        coeffs.append(ring_from_shake(shakes[id]))
    return RR(coeffs)

def extended_euclid(a,b):
    r0 = a; r1 = b
    s0 = 1; s1 = 0
    t0 = 0; t1 = 1

    while r1 != 0:
        q, r = r0.quo_rem(r1)
        r0, r1 = r1, r
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    return r0, s0, t0

def RR_inverse(x):
    gcd, inv, _ = extended_euclid(x, POLY)
    assert(gcd.degree() == 0)
    assert(gcd != 0)
    assert(gcd[0] % 2 == 1)
    assert((x * inv).quo_rem(POLY)[1] == gcd)
    assert((x * inv * gcd[0]^(-1)).quo_rem(POLY)[1] == 1)
    return inv * gcd[0]^(-1)

def reduce_poly_RR(x):
    poly = []
    for coeff in x.coefficients():
        poly.append(coeff.quo_rem(POLY)[1])
    return PolyR(poly)



def interpolate(evals, lagrange_polys):
    assert(len(evals) >= len(lagrange_polys))

    res = PolyR(0)

    for i in range(len(evals)):
        res += evals[i] * lagrange_polys[i]

    return reduce_poly_RR(res)

def c(f):
    assert(len(f) == 6)
    res = f[0] * f[2] + f[0] * f[3] + f[1] * f[2] + f[4] - f[5]
    return res

def g(thetas, f):
    assert(len(thetas) == L)
    assert(len(f) == 6*L)
    res = 0
    for i in range(L):
        res += thetas[i] * c(f[6*i:6*(i+1)])
    return res

def proof_0():
    global P0_0_input
    # Round1
    # a)
    shake = coin()
    thetas = []
    for _ in range(L):
        thetas.append(poly_from_shake(shake))
    # b) Just P0
    w = []
    for i in range(6*L):
        w.append(poly_from_rand())
    # c) Just P0
    f = []
    for p in P0_0_input:
        assert(c(p).quo_rem(POLY)[1] == 0)
    for j in range(L):
        for i in range(6):
            evals = []
            evals.append(w[i * L + j])
            for l in range(M):
                evals.append(P0_0_input[j * M + l][i])
            f_ = interpolate(evals, lagrange)
            for i in range(len(evals)):
                assert(f_(x_coord[i]).quo_rem(POLY)[1] == evals[i])
            f.append(f_)
    # d) Just P0
    g_ = reduce_poly_RR(g(thetas, f))
    # e) Just P0
    pi_1 = []
    pi_2 = []
    for i in range(6 * L):
        pi_1.append(poly_from_rand())
        pi_2.append((w[i] - pi_1[i]).quo_rem(POLY)[1])
    assert(len(g_.coefficients()) == 2 * M + 1) # otherwise we need to pad with zeros
    for i in range(2 * M + 1):
        pi_1.append(poly_from_rand())
        pi_2.append((g_[i] - pi_1[i + 6 * L]).quo_rem(POLY)[1])

    return pi_1, pi_2, thetas

def verify_0(pi_1, pi_2, thetas):
    # Round2
    # a)
    shake = coin()
    betas = []
    for _ in range(M):
        betas.append(poly_from_shake(shake))
    r = poly_from_shake(shake)
    while r[1] == 0: # is this the correct check?
        r = poly_from_shake(shake)

    # b)
    eval_f_1, pr_1, b_1 = verify_p1(pi_1, betas, r)
    eval_f_2, pr_2, b_2 = verify_p2(pi_2, betas, r)

    # Round3
    eval_f = []
    for i in range(6*L):
        eval_f.append(eval_f_1[i] + eval_f_2[i])
    pr_ = g(thetas, eval_f).quo_rem(POLY)[1]

    pr = (pr_1 + pr_2).quo_rem(POLY)[1]
    b = (b_1 + b_2).quo_rem(POLY)[1]

    assert(pr == pr_)
    assert(b == 0)

def verify_p1(pi_1, betas, r):
    global P1_0_input

    # ii)
    f = []
    for j in range(L):
        for i in range(6):
            evals = []
            evals.append(pi_1[i * L + j])
            for l in range(M):
                evals.append(P1_0_input[j * M + l][i])
            f_ = interpolate(evals, lagrange)
            for i in range(len(evals)):
                assert(f_(x_coord[i]).quo_rem(POLY)[1] == evals[i])
            f.append(f_)

    # iii)
    eval_f = []
    for i in range(6*L):
        eval_f.append(f[i](r))

    pr = 0
    r_pow = 1
    for i in range(2 * M + 1):
        pr += pi_1[i + 6 * L] * r_pow
        r_pow *= r

    # iv)
    b = 0
    for i in range(M):
        j = x_coord[i + 1]
        j_pow = 1
        sum = 0
        for k in range(2 * M + 1):
            sum += pi_1[k + 6 * L] * j_pow
            j_pow *= j
        sum *= betas[i]
        b += sum

    return eval_f, pr, b



def verify_p2(pi_2, betas, r):
    global P2_0_input

    # ii)
    f = []
    for j in range(L):
        for i in range(6):
            evals = []
            evals.append(pi_2[i * L + j])
            for l in range(M):
                evals.append(P2_0_input[j * M + l][i])
            f_ = interpolate(evals, lagrange)
            for i in range(len(evals)):
                assert(f_(x_coord[i]).quo_rem(POLY)[1] == evals[i])
            f.append(f_)

    # iii)
    eval_f = []
    for i in range(6*L):
        eval_f.append(f[i](r))

    pr = 0
    r_pow = 1
    for i in range(2 * M + 1):
        pr += pi_2[i + 6 * L] * r_pow
        r_pow *= r

    # iv)
    b = 0
    for i in range(M):
        j = x_coord[i + 1]
        j_pow = 1
        sum = 0
        for k in range(2 * M + 1):
            sum += pi_2[k + 6 * L] * j_pow
            j_pow *= j
        sum *= betas[i]
        b += sum

    return eval_f, pr, b



init_shakes()

for _ in range(m):
    a = ring_from_shake(tester)
    b = ring_from_shake(tester)
    a_ = share(a)
    b_ = share(b)

    c_ = mul(a_, b_)

pi_1, pi_2, thetas = proof_0()
verify_0(pi_1, pi_2, thetas)
