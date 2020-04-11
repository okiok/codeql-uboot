import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(Macro m, MacroInvocation mi | 
        m.getName().regexpMatch("ntoh[a-z]*") and 
        mi.getMacro() = m and
        mi.getExpr() = this)
  } 
}

from NetworkByteSwap n
select n, "Network byte swap" 

