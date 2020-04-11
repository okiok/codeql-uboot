import cpp

from Macro m, MacroInvocation inv, Expr e
where m.getName().regexpMatch("ntoh[a-z]*") and 
    inv.getMacro() = m
select inv.getExpr()
//