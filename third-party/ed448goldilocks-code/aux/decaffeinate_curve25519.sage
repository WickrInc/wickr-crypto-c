# This is as sketch of how to decaffeinate Curve25519

F = GF(2^255-19)

doPinkBikeShed = True

if doPinkBikeShed: d = -89747 # PinkBikeShed
else: d = -121665 # Curve25519

M = EllipticCurve(F,[0,2-4*d,0,1,0])
    
sqrtN1 = sqrt(F(-1))
    
def maybe(): return randint(0,1)

def qpositive(x):
    return int(x) <= (2^255-19-1)/2

def M_to_E(P):
    # P must be even
    (x,y) = P.xy()
    assert x.is_square()
    
    s = sqrt(x)
    if s == 0: t = 1
    else: t = y/s
    
    X,Y = 2*s / (1+s^2), (1-s^2) / t
    if maybe(): X,Y = -X,-Y
    if maybe(): X,Y = Y,-X
    # OK, have point in ed
    return X,Y

def decaf_encode_from_E(X,Y):
    assert X^2 + Y^2 == 1 + d*X^2*Y^2
    if not (X==0 or Y==0 or qpositive(1/(X*Y)) or doPinkBikeShed): X,Y = Y,-X
    assert X==0 or Y==0 or qpositive(1/(X*Y))
    
    assert (1-X^2).is_square()
    sx = sqrt(1-X^2)
    tos = -2*sx/X/Y
    if not qpositive(tos): sx = -sx
    s = (1 + sx) / X
    if not qpositive(s): s = -s
    
    return s

def isqrt(x):
    ops = [(1,2),(1,2),(3,1),(6,0),(1,2),(12,1),(25,1),(25,1),(50,0),(125,0),(2,2),(1,2)]
    st = [x,x,x]
    for i,(sh,add) in enumerate(ops):
        od = i&1
        st[od] = st[od^^1]^(2^sh)*st[add]
    # assert st[2] == x^(2^252-3)
    
    assert st[1] == 1 or st[1] == -1
    if st[1] == 1: return st[0]
    else: return st[0] * sqrtN1

def decaf_encode_from_E_c(X,Y):
    Z = F.random_element()
    T = X*Y*Z
    X = X*Z
    Y = Y*Z
    assert X^2 + Y^2 == Z^2 + d*T^2
    
    # Precompute
    sd = sqrt(F(1-d))
    
    # comments in case of identity point
    # (1,0) or (0,1)
    zx = Z^2-X^2 # 0^2 or 1 * Z^2
    TZ = T*Z # 0 * Z^2
    assert zx.is_square
    ooAll = isqrt(zx*TZ^2) # inf^2 or inf * 1/Z^3
    osx = ooAll * TZ # inf or 1 * 1/Z
    ooTZ = ooAll * zx * osx # inf * 1/Z^2
    
    floop = qpositive(Z^2 * ooTZ) or doPinkBikeShed # 0
    if floop:
        frob = zx * ooTZ # 0 or inf
        # Y = 0 or 1
    else:
        frob = sd # sd
        Y = -X # -1 or 0 * Z
        
    osx *= frob # 1 or inf * 1/Z || inf sd or sd * 1/Z
    # y * osx = 0 or inf or -inf sd or 0 sd
    # y * ootz * z = 1 or inf or inf sd or 0^2 sd
    # s = 0 or 1 or inf sd or 
    
    if qpositive(-2*osx*Z) != floop: osx = -osx
    s = Y*(ooTZ*Z + osx) # 
    if not qpositive(s): s = -s
    
    return s
    
def is_rotation((X,Y),(x,y)):
    return x*Y == X*y or x*X == -y*Y
    
def decaf_decode_to_E(s):
    assert qpositive(s)
    t = sqrt(s^4 + (2-4*d)*s^2 + 1)
    if not qpositive(t/s): t = -t
    X,Y = 2*s / (1+s^2), (1-s^2) / t
    assert X==0 or Y==0 or qpositive(1/(X*Y)) or doPinkBikeShed
    return X,Y
    
def decaf_decode_to_E_c(s):
    assert qpositive(s)
    
    s2 = s^2
    s21 = 1+s2
    t2 = s21^2 - 4*d*s2
    
    alt  = s21*s
    the  = isqrt(t2*alt^2)
    oot  = the * alt
    the *= t2
    tos  = the * s21
    X = 2 * (tos-the) * oot
    Y = (1-s2) * oot
    
    if not qpositive(tos): Y = -Y
    assert qpositive(X*Y) or doPinkBikeShed
    
    return X,Y

def test():
    P = 2*M.random_point()
    X,Y = M_to_E(P)
    s = decaf_encode_from_E(X,Y)
    assert s == decaf_encode_from_E_c(X,Y)
    XX,YY = decaf_decode_to_E(s)
    XX2,YY2 = decaf_decode_to_E_c(s)
    assert is_rotation((X,Y),(XX,YY))
    assert is_rotation((X,Y),(XX2,YY2))


    