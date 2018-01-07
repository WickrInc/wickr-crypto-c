from idealized import Idealized
from collections import namedtuple

debugging = True
def debug_print(foo):
    if debugging: print foo

checkGroupLaws = True
checkTorsion = True
checkIsogenies = True

def memoize(f):
    # list cache because my __hash__ hack doesn't seem to work
    cache = []
    def ff(*args, **kwargs):
        key = (tuple(args),tuple(sorted(kwargs.iteritems())))
        for key_,value in cache:
            if key == key_: return value
        out = f(*args,**kwargs)
        cache.append((key,out))
        return out   
        
    try:
        ff.__name__ = f.__name__
    except AttributeError: pass
    return ff

def EcBase(curvename,varnames,ad=()):
    if isinstance(ad,str) or isinstance(ad[0],str):
        ad = Idealized.vars(ad)
    
    class Inner(namedtuple(curvename,(v for v in varnames))):
        params = ad
        torsion_points = {}
        def __new__(cls,*xy):
            def apply_invariants(xy,x):
                for inv in cls.invariants(*(ad+xy)):
                    x = x.assuming(inv)
                return x
            
            xy = tuple(xy)
            if len(xy) == 0:
                xy = Idealized.uvars(varnames)
                xy = [apply_invariants(xy,x) for x in xy]
            else:
                for i,inv in enumerate(cls.invariants(*(ad + xy))):
                    if inv != 0:
                        raise Exception("Invariant inv[%d] not satisfied for %s: got \n%s" %
                             (i,curvename,str(inv)))

            return super(Inner,cls).__new__(cls,*xy)
                    
        varnames = "xy"
        
        @classmethod
        def invariants(self,*args): return []
        
        @classmethod
        @memoize
        def check_group(cls):
            if checkGroupLaws:
                debug_print("Checking group law for %s..." % cls.__name__)
                a,b,c,z = cls(),cls(),cls(),cls.basepoint
                if a+z != a:
                    raise Exception("Base point is not identity!")
                if a-a != z:
                    raise Exception("Subtraction doesn't work!")
                if a+b != b+a:
                    raise Exception("Addition is not commutative!")
                #if a+(b+c) != (a+b)+c:
                #    raise Exception("Addition is not associative!")
            
            for t,n in cls.torsion():
                if checkTorsion:
                    debug_print("  Checking %d-torsion..." % n)
                    cls.check_torsion(t,n)
                #if n not in cls.torsion_points:
                #    cls.torsion_points[n] = set()
                #cls.torsion_points[n].add(cls(*t(cls.basepoint)))
                
        @classmethod
        def check_torsion(cls,f,n):
            P = Q = cls()
            good = False
            for i in xrange(1,n+1):
                Q = cls(*f(Q))
                if Q == P:
                    if i==n:
                        good = True
                        break
                    raise Exception("Claimed %d-torsion, but is actually %d-torsion" % (n,i))
            if not good: raise Exception("Claimed %d-torsion, but isn't" % n)
            if n*P+n*cls(*f(P)) == cls.basepoint:
                raise Exception("Torsion operation inverts element")
        
        @classmethod
        def torsion(cls):
            return []
        
        def __sub__(self,other):
            return self + (-other)
            
        def __mul__(self,other):
            if other==0: return self.basepoint
            if other < 0: return -(self*-other)
            if other==1: return self
            if is_even(other): return (self+self)*(other//2)
            return (self+self)*(other//2) + self
        
        def __rmul__(self,other):
            return self*other
            
    Inner.__name__ = curvename + "_base"
    return Inner

class Isogeny(object):

    isograph = DiGraph(weighted=True)
    isomap = {}
    
    @classmethod
    def generate(cls, fro, to):
        path = cls.isograph.shortest_path(fro,to,by_weight=True)
        if len(path):
            iso = cls.isomap[(path[0], path[1])]
            for i in xrange(1,len(path)-1):
                iso = cls.isomap[(path[i],path[i+1])].compose(iso)
            return iso
        else:
            return None
    
    def __init__(self,c1,c2,deg,fw,rv,check=True,dual=None,add=True):
        self.c1 = c1
        self.c2 = c2
        self.fw = fw
        self.rv = rv
        self.deg = deg
        
        if add:
            Isogeny.isomap[(c1,c2)] = self
            Isogeny.isograph.add_edge(c1,c2,log(deg)/log(2) + 0.1)
        
        if dual is not None:
            self.dual = dual
        else:
            self.dual = Isogeny(c2,c1,deg,rv,fw,False,self,add)
        if not check: return
        
        
        if not checkIsogenies: return
        
        debug_print("Checking isogeny %s <-%d-> %s..." % (c1.__name__,deg,c2.__name__))
        if c2(*fw(*c1.basepoint)) != c2.basepoint:
            raise Exception("Isogeny doesn't preserve basepoints")
        if c1(*fw(*c2.basepoint)) != c1.basepoint:
            raise Exception("Isogeny dual doesn't preserve basepoints")
            
        foo = c1()
        bar = c2()
        
        c2(*fw(*foo))
        c1(*rv(*bar))
        
        if c1(*rv(*c2(*fw(*foo)))) != deg*foo:
            raise Exception("Isogeny degree is wrong")
        if c2(*fw(*c1(*rv(*bar)))) != deg*bar:
            raise Exception("Isogeny degree is wrong")
        if -c2(*fw(*foo)) != c2(*fw(*(-foo))):
            raise Exception("Isogeny uses wrong negmap")
        if -c1(*rv(*bar)) != c1(*rv(*(-bar))):
            raise Exception("Isogeny uses wrong negmap")
            
        
    def __call__(self,ipt,**kwargs):
        return self.c2(*self.fw(*ipt,**kwargs))
        
    def __repr__(self): return str(self)
    def __str__(self):
        out = "Isogeny %s%s <-%d-> %s%s..." %\
            (self.c1.__name__,str(self.c1.params),self.deg,
                self.c2.__name__,self.c2.params)
        out += "\n  fw: %s" % str(self(self.c1()))
        out += "\n  rv: %s" % str(self.dual(self.c2()))
        return out
        
    def compose(self,other):
        def fw(*args): return self.fw(*other.fw(*args))
        def rv(*args): return other.rv(*self.rv(*args))
        return Isogeny(other.c1,self.c2,self.deg*other.deg,fw,rv,False,None,False)

def ec_family(defs,vars):
    def inner1(CLS):
        @memoize
        def inner2(*args,**kwargs):
            if len(args)==0 and len(kwargs)==0:
                args = tuple(defs)
                chk = True
            else:
                chk = False
            
            class ret(CLS,EcBase(CLS.__name__,vars,args)):
                def __new__(cls,*args,**kwargs):
                    return super(ret,cls).__new__(cls,*args,**kwargs)
                
            ret.__name__ = CLS.__name__
            ret.basepoint = ret(*ret.get_basepoint())
                
            if chk: ret.check_group()
            return ret
            
        inner2.__name__ = CLS.__name__ + "_family"
        inner2()
        return inner2
        
    return inner1

#checkGroupLaws = checkTorsion = False

@ec_family("ad","xy")
class Edwards:
    @classmethod
    def invariants(cls,a,d,x,y):
        return [y^2 + a*x^2 - 1 - d*x^2*y^2]
        
    def __neg__(self):
        return self.__class__(-self.x,self.y)
    
    def __add__(self,other):
        (x,y) = self
        (X,Y) = other
        a,d = self.params
        dd = d*x*X*y*Y
        return self.__class__((x*Y+X*y)/(1+dd),(y*Y-a*x*X)/(1-dd))

    @classmethod
    def get_basepoint(cls): return (0,1)

    @classmethod
    @memoize
    def torsion(cls):
        a,d = cls.params
        sa = a.sqrt()
        sd = d.sqrt()
        sad = (a*d).sqrt()
        def tor2_1((x,y)): return (-x,-y)
        def tor4_1((x,y)): return (y/sa,-x*sa)
        def tor4_2((x,y)): return (1/(sd*y),-1/(sd*x))
        def tor2_2((x,y)): return (-1/(sad*x),-a/(sad*y))
        
        return [(tor2_1,2),(tor2_2,2),(tor4_1,4),(tor4_2,4)]

@ec_family("eA","st")
class JacobiQuartic:
    @classmethod
    def invariants(cls,e,A,s,t):
        return [-t^2 + e*s^4 + 2*A*s^2 + 1]
        
    def __neg__(self):
        return self.__class__(-self.s,self.t)
    
    def __add__(self,other):
        (x,y) = self
        (X,Y) = other
        e,A = self.params
        dd = e*(x*X)^2
        YY = (1+dd)*(y*Y+2*A*x*X) + 2*e*x*X*(x^2+X^2)
        return self.__class__((x*Y+X*y)/(1-dd),YY/(1-dd)^2)

    @classmethod
    def get_basepoint(cls): return (0,1)

    @classmethod
    @memoize
    def torsion(cls):
        e,A = cls.params
        se = e.sqrt()
        def tor2_1((s,t)): return (-s,-t)
        def tor2_2((s,t)): return (1/(se*s),-t/(se*s^2))
        return [(tor2_1,2),(tor2_2,2)]

a,d = Idealized.vars("ad")
def phi_iso(a,d):
    return Isogeny(Edwards(a,d),JacobiQuartic(a^2,a-2*d),
        2,
        lambda x,y: (x/y, (2-y^2-a*x^2)/y^2),
        lambda s,t: (2*s/(1+a*s^2), (1-a*s^2)/t)
    )

print phi_iso(a,d)
print phi_iso(-a,d-a)

print Isogeny.generate(Edwards(a,d),Edwards(-a,d-a))