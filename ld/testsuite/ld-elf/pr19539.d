#source: start.s
#source: pr19539.s
#ld: -pie -T pr19539.t
#readelf : --dyn-syms --wide
#target: *-*-linux* *-*-gnu* *-*-solaris* arm*-*-uclinuxfdpiceabi
#xfail: cris*-*-* h8300-*-*

Symbol table '\.dynsym' contains [0-9]+ entr(y|ies):
#pass
