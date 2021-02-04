SHELL := /bin/bash  # so as to be able to use bashisms in Makefile
LABEL := \s*\(\([1-9a-f][0-9a-f]*\|0\):\)
DUMP  := \s\+\([0-9a-f]\{8\}\)
INSTR := \(\s\+[0a-z][a-z0-9.]*\)
ARG   := \(\s*[^ ]*\)
SUBST := s%^$(LABEL)$(DUMP)$(INSTR)$(ARG)$$%\4\5  \# \1 \3%
REGSUBST := s/\<\(zero\|at\|[vk][01]\|a[0-3]\|[st][0-9]\|[gsf]p\|ra\)\>/$$\1/g
INSERT := s/^\(\w\+:\)\?\(\s\+\)\(0x\)/\1\2.word\t\3/
MATCH := ^$(LABEL)$(DUMP)$(INSTR)$(ARG)$
VERBOSE ?= -OO  # quiet by default
SIDEBYSIDE ?= -y  # set to empty string for normal diff
export
check: 0.img
%.img: %.asm mips.py
	python $(VERBOSE) mips.py assemble $< > $@tmp
	mv $@tmp $@
%.asm: %.dat
	python $(VERBOSE) mips.py disassemble $< > $@tmp
	mv $@tmp $@
debug:
	$(MAKE) VERBOSE= check
%.xxd: %.dat
	xxd -a $< $@
%.diff: %.dis %.asm
	diff $(SIDEBYSIDE) -w \
	 <(sed -e 's/^[^\t .]\S\+//' -e 's/#.*$$//' $<) \
	 <(sed -e 's/^[^\t .]\S\+//' -e 's/#.*$$//' $(word 2, $+))
%.bindiff: %.out
	diff %.dat %.out
%.disout: %.dis
	mips-linux-gnu-as -mips4 -o $@ $<
%.asmout: %.asm
	mips-linux-gnu-as -mips4 -o $@ $<
%.dsm: %.dat Makefile
	mips-linux-gnu-objdump \
	 --disassemble-all \
	 --disassemble-zeroes \
	 --target=binary \
	 --architecture=mips:4000 $< > $@
%.dis: %.dsm Makefile # cleanup objdump disassembly
	echo '.set noat' > $@
	sed -n -e '$(SUBST)p' $< | \
	 sed -e '$(INSERT)' | \
	 sed -e '$(REGSUBST)' >> $@
%.sedcheck:  %.dsm  # for checking sed patterns
	sed -n '/$(MATCH)/p' $< > $@
	diff $< $@
%: %.S
	mips-linux-gnu-gcc $< -o $@
.FORCE:
