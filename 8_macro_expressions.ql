import cpp

from Macro m, MacroInvocation inv
where m.getName().regexpMatch("ntoh[a-z]*") and 
    inv.getMacro() = m
select inv.getExpr()
//