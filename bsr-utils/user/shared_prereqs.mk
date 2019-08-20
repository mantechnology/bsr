# to be included from user/v*/Makefiles

../shared/%:
	$(MAKE) -C $(@D) $(@F)
bsr_buildtag.o: ../shared/bsr_buildtag.c

# from make documentation, automatic prerequisites
.%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

.bsrmeta_scanner.d: ../shared/bsrmeta_scanner.c
all-dep = $($(filter-out bsr_buildtag.o,$(all-obj)):%.o=.%.d)

ifneq (,$(filter-out clean distclean,$(MAKECMDGOALS)))
include $(all-dep)
endif
