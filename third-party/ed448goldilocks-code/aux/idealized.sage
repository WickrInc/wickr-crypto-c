class Unique(object):
    def __init__(self,name):
        self.name = name
    
    def __str__(self):
        return self.name
    
    def __repr__(self):
        return "Unique(\"%s\")" % self.name

class Idealized(object):
    UNION = ["UNION"]
    
    def __init__(self, R, idealMap = 0, vars = {}):
        self.varnames = vars
        if not isinstance(idealMap,dict):
            idealMap = {()*R:idealMap}
        self.idealMap = idealMap
        self.R = R
        self._sqrt = None
        self._isqrt = None
    
    @staticmethod
    def uvar(x):
        return Idealized.var(Unique(x))
    
    @staticmethod
    def var(x):
        name = str(x)
        R = PolynomialRing(QQ,[name])
        rx = R.gens()[0]
        return Idealized(R,rx,{x:(name,rx)})
    
    @staticmethod
    def vars(xs):
        return tuple((Idealized.var(x) for x in xs))
    
    @staticmethod
    def uvars(xs):
        return tuple((Idealized.uvar(x) for x in xs))
    
    def __str__(self):
        def rep(I,x):
            x = str(x)
            gs = I.gens()
            gs = [g for g in gs if g != 0]
            if len(gs) == 0: return x
            else:
                g = ", ".join(["(%s)" % str(gen) for gen in gs])
                return g + ": " + x
        return "\n".join([rep(I,self.idealMap[I]) for I in self.idealMap])
    
    def __repr__(self):
        # HACK!
        if len(self.idealMap) == 0:
            return "undef"
        if len(self.idealMap) > 1:
            return str(self)
        for _,v in self.idealMap.iteritems():
            return str(v)
        
    def prune(self):
        self.idealMap = {I:v for I,v in self.idealMap.iteritems() if not (I*self.R).is_one()}
        return self
        
    def __add__(self,other):
        def f(x,y): return x+y
        return self.op(other,f)
        
    def __radd__(self,other):
        def f(x,y): return y+x
        return self.op(other,f)
        
    def __rsub__(self,other):
        def f(x,y): return y-x
        return self.op(other,f)
        
    def __neg__(self):
        def f(x,y): return y-x
        return self.op(0,f)
        
    def __sub__(self,other):
        def f(x,y): return x-y
        return self.op(other,f)
        
    def is_square(self):
        for _,v in self.idealMap.iteritems():
            if not is_square(v): return False
        return True
        
    def sqrt(self):
        if self._sqrt is None:
            s = Idealized.uvar("s")
            self._sqrt = s.assuming(s^2 - self)
        return self._sqrt
        
    def isqrt(self):
        if self._isqrt is None:
            s = Idealized.uvar("s")
            z = Idealized(0).assuming(Self)
            self._isqrt = s.assuming(s^2*self-1).union(z)
        return self._isqrt
        
    def __mul__(self,other):
        def f(x,y): return x*y
        return self.op(other,f)
        
    def __rmul__(self,other):
        def f(x,y): return y*x
        return self.op(other,f)
    
    def __pow__(self,n):
        if n < 0: return 1/self^(-n)
        if n == 0: return 1
        if n == 1: return self
        if is_even(n): return (self*self)^(n//2)
        if is_odd(n): return (self*self)^(n//2) * self
        
    def __div__(self,other):
        def f(x,y): return x/y
        return self.op(other,f)
        
    def __rdiv__(self,other):
        def f(x,y): return y/x
        return self.op(other,f)
        
    def union(self,other):
        return self.op(other,Idealized.UNION)
        
    def __eq__(self,other):
        return (self - other).is_zero()
        
    def __ne__(self,other):
        return not (self==other)
        
    def __hash__(self):
        return 0

    def assume_zero(self):
        out = {}
        for I,J in self.idealMap.iteritems():
            IJ = I+J.numerator()
            if IJ.is_one(): continue
            out[IJ] = self.R(0)
        
        if len(out) == 0:
            raise Exception("Inconsistent assumption")
        
        return Idealized(self.R,out,self.varnames)
    
    def assuming(self,other):
        return self + other.assume_zero()
    
    def is_zero(self):
        for I,v in self.idealMap.iteritems():
            if v.denominator() in I: return False
            if v.numerator() not in I: return False
        return True
    
    def op(self,other,f):
        if not isinstance(other,Idealized):
            other = Idealized(self.R,other,self.varnames)
        
        bad = False
        for v in self.varnames:
            if v not in other.varnames or self.varnames[v] != other.varnames[v]:
                bad = True
                break
        for v in other.varnames:
            if v not in self.varnames or self.varnames[v] != other.varnames[v]:
                bad = True
                break
                
        if bad:
            def incrVar(v):
                if v[-1] not in "0123456789": return v + "1"
                elif v[-1] == 9: return incrVar(v[:-1]) + "0"
                else: return v[:-1] + str(int(v[-1])+1)
        
            vars = {}
            names = set()
            for v,(name,_) in self.varnames.iteritems():
                assert(name not in names)
                names.add(name)
                vars[v] = name
            subMe = {n:n for n in names}
            subThem = {}
            for v,(name,_) in other.varnames.iteritems():
                if v in self.varnames:
                    subThem[name] = self.varnames[v][0]
                else:
                    oname = name
                    while name in names:
                        name = incrVar(name)
                    names.add(name)
                    subThem[oname] = name
                    vars[v] = name
            
            R = PolynomialRing(QQ,sorted(list(names)),order="degrevlex")
            gd = R.gens_dict()
            subMe = {m:gd[n] for m,n in subMe.iteritems()}
            subThem = {m:gd[n] for m,n in subThem.iteritems()}
        
            vars = {v:(n,gd[n]) for v,n in vars.iteritems()}
        
            def subIdeal(I,sub):
                return [g(**sub) for g in I.gens()]*R
            idealMe = {subIdeal(I,subMe):v(**subMe) for I,v in self.idealMap.iteritems()}
            idealThem = {subIdeal(I,subThem):v(**subThem) for I,v in other.idealMap.iteritems()}
        else:
            R = self.R
            idealMe = self.idealMap
            idealThem = other.idealMap
            vars = self.varnames
        
        def consist(I,x,y):
            if (x-y).numerator() not in I:
                raise Exception("Inconsistent: %s != %s in ideal %s" %
                    (str(x),str(y),str(I)))
            
        out = {}
        if f is Idealized.UNION:
            for I,v in idealMe.iteritems():
                if I in idealThem:
                    consist(I,v,idealThem[I])
                out[I] = v
            for I,v in idealThem.iteritems():
                if I in idealMe:
                    consist(I,v,idealMe[I])
                out[I] = v
        
        else:
            for I,v in idealMe.iteritems():
                if I in idealThem:
                    x = f(v,idealThem[I])
                    if I in out:
                        consist(I,x,out[I])
                    else: out[I] = x
                else:
                    for J,w in idealThem.iteritems():
                        IJ = I+J
                        if not IJ.is_one():
                            x = f(v,w)
                            if IJ in out:
                                consist(IJ,x,out[IJ])
                            else:
                                out[IJ] = x
        
        def gb(I):
            II = [0]*R
            for g in I.gens():
                if g not in II: II = II+[g]*R
            return II

        def red(I,v):
            if I.is_zero(): return v
            return I.reduce(R(v.numerator())) / I.reduce(R(v.denominator()))
            
        out = {gb(I):v for I,v in out.iteritems()}
        out = {I:red(I,v) for I,v in out.iteritems()}
        
        return Idealized(R,out,vars)
    
    def reduce(self):
        def red(I,v):
            if I.is_zero(): return v
            return I.reduce(R(v.numerator())) / I.reduce(R(v.denominator()))
        out = {I:red(I,v) for I,v in self.idealMap.iteritems()}
        return Idealized(self.R,out,self.vars)

Idealized.INF = Idealized.uvar("inf")
Idealized.ZOZ = Idealized.uvar("zoz")
    