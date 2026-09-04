BUILD=debug
CXX = clang++
cxxflags.debug   = -O0 -g
cxxflags.release = -O3 -g
# CATCH_CONFIG_NO_POSIX_SIGNALS: catch's signal handler uses SIGSTKSZ as an
# array bound, which is no longer a constant with glibc >= 2.34.
CXXFLAGS = ${cxxflags.${BUILD}} -std=c++14 -Wall $(INCLUDE) -DCATCH_CONFIG_NO_POSIX_SIGNALS

src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

build: systemCallTests

systemCallTests: $(obj)
	$(CXX) $^ -o $@

run: systemCallTests
	../../bin/dettrace ./systemCallTests | tee .unit-test-output
	@grep --quiet "All tests passed" .unit-test-output
	make -C ./otherClassesTests/ run

-include $(dep)

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cpp
	@g++ $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean build
clean:
	$(RM) $(obj)
	$(RM) $(dep)
	$(RM) systemCallTests
	make -C ./otherClassesTests clean
# Credits to the awesome makefile guide:
# http://nuclear.mutantstargoat.com/articles/make/
