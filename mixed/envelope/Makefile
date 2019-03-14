CXX = c++
CXXFLAGS = -Wall -Wextra
JAVAC = javac
JAVAFLAGS = -Xlint:all
VALGRIND =

all:	\
	EncryptUtilTest \
	EncryptUtil.class \
	$(NULL)

clean:
	-rm EncryptUtilTest EncryptUtil.class

check:	all
	java EncryptUtil
	$(VALGRIND) ./EncryptUtilTest

EncryptUtil.cxx: EncryptUtil.h
EncryptUtilTest.cxx: EncryptUtil.h

EncryptUtilTest:	\
		EncryptUtil.cxx \
		EncryptUtilTest.cxx \
		$(NULL)
	$(CXX) $(CXXFLAGS) -o $@ $^ -l crypto

EncryptUtil.class: EncryptUtil.java
	$(JAVAC) $(JAVAFLAGS) $<
