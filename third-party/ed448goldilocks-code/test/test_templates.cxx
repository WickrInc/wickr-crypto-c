#include "decaf/expr.hxx"

class Foo {
private:
    template<BinOp OP, class L, class R, class T> friend class BinExpr;
    template<UnOp OP, class R, class T> friend class UnExpr;
    template<class T> friend struct Reify;
    Foo(const NOINIT&) {}
public:
    int x;
    Foo(int x) : x(x) {}
};

namespace decaf { namespace internal {
DECLARE_BINOP(ADD,Foo,Foo,Foo,out.x = l.x+r.x)
DECLARE_BINOP(SUB,Foo,Foo,Foo,out.x = l.x-r.x)
DECLARE_BINOP(MUL,Foo,Foo,Foo,out.x = l.x*r.x)
DECLARE_BINOP(EQ,Foo,Foo,bool,out = l.x==r.x)
DECLARE_PARTIAL_UNOP(INV,Foo,Foo,out.x = 1/r.x; return (r.x!=0))
}}

Foo frobble() {
    Foo a(1);
    a = a+a+a;
    a = a*a;
    a = a/a;
    (void)(a==(a+a));
    return a;
}
