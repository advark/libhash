#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Release
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/src/crc32.o \
	${OBJECTDIR}/src/hashbase.o \
	${OBJECTDIR}/src/md5.o \
	${OBJECTDIR}/src/sha1.o \
	${OBJECTDIR}/src/sha2.o

# Test Directory
TESTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}/tests

# Test Files
TESTFILES= \
	${TESTDIR}/TestFiles/f2

# Test Object Files
TESTOBJECTFILES= \
	${TESTDIR}/tests/CRC32Tests.o \
	${TESTDIR}/tests/MD5Tests.o \
	${TESTDIR}/tests/SHA1Tests.o \
	${TESTDIR}/tests/SHA2Tests.o \
	${TESTDIR}/tests/libHashTest.o \
	${TESTDIR}/tests/libHashTestCases.o

# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/liblibhash.${CND_DLIB_EXT}

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/liblibhash.${CND_DLIB_EXT}: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/liblibhash.${CND_DLIB_EXT} ${OBJECTFILES} ${LDLIBSOPTIONS} -shared -fPIC

${OBJECTDIR}/src/crc32.o: src/crc32.cpp
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/crc32.o src/crc32.cpp

${OBJECTDIR}/src/hashbase.o: src/hashbase.cpp
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/hashbase.o src/hashbase.cpp

${OBJECTDIR}/src/md5.o: src/md5.cpp
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/md5.o src/md5.cpp

${OBJECTDIR}/src/sha1.o: src/sha1.cpp
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/sha1.o src/sha1.cpp

${OBJECTDIR}/src/sha2.o: src/sha2.cpp
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -fPIC  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/sha2.o src/sha2.cpp

# Subprojects
.build-subprojects:

# Build Test Targets
.build-tests-conf: .build-tests-subprojects .build-conf ${TESTFILES}
.build-tests-subprojects:

${TESTDIR}/TestFiles/f2: ${TESTDIR}/tests/CRC32Tests.o ${TESTDIR}/tests/MD5Tests.o ${TESTDIR}/tests/SHA1Tests.o ${TESTDIR}/tests/SHA2Tests.o ${TESTDIR}/tests/libHashTest.o ${TESTDIR}/tests/libHashTestCases.o ${OBJECTFILES:%.o=%_nomain.o}
	${MKDIR} -p ${TESTDIR}/TestFiles
	${LINK.cc} -o ${TESTDIR}/TestFiles/f2 $^ ${LDLIBSOPTIONS}  -lcppunit 


${TESTDIR}/tests/CRC32Tests.o: tests/CRC32Tests.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/CRC32Tests.o tests/CRC32Tests.cpp


${TESTDIR}/tests/MD5Tests.o: tests/MD5Tests.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/MD5Tests.o tests/MD5Tests.cpp


${TESTDIR}/tests/SHA1Tests.o: tests/SHA1Tests.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/SHA1Tests.o tests/SHA1Tests.cpp


${TESTDIR}/tests/SHA2Tests.o: tests/SHA2Tests.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/SHA2Tests.o tests/SHA2Tests.cpp


${TESTDIR}/tests/libHashTest.o: tests/libHashTest.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/libHashTest.o tests/libHashTest.cpp


${TESTDIR}/tests/libHashTestCases.o: tests/libHashTestCases.cpp 
	${MKDIR} -p ${TESTDIR}/tests
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${TESTDIR}/tests/libHashTestCases.o tests/libHashTestCases.cpp


${OBJECTDIR}/src/crc32_nomain.o: ${OBJECTDIR}/src/crc32.o src/crc32.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	@NMOUTPUT=`${NM} ${OBJECTDIR}/src/crc32.o`; \
	if (echo "$$NMOUTPUT" | ${GREP} '|main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T _main$$'); \
	then  \
	    ${RM} "$@.d";\
	    $(COMPILE.cc) -O2 -fPIC  -Dmain=__nomain -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/crc32_nomain.o src/crc32.cpp;\
	else  \
	    ${CP} ${OBJECTDIR}/src/crc32.o ${OBJECTDIR}/src/crc32_nomain.o;\
	fi

${OBJECTDIR}/src/hashbase_nomain.o: ${OBJECTDIR}/src/hashbase.o src/hashbase.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	@NMOUTPUT=`${NM} ${OBJECTDIR}/src/hashbase.o`; \
	if (echo "$$NMOUTPUT" | ${GREP} '|main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T _main$$'); \
	then  \
	    ${RM} "$@.d";\
	    $(COMPILE.cc) -O2 -fPIC  -Dmain=__nomain -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/hashbase_nomain.o src/hashbase.cpp;\
	else  \
	    ${CP} ${OBJECTDIR}/src/hashbase.o ${OBJECTDIR}/src/hashbase_nomain.o;\
	fi

${OBJECTDIR}/src/md5_nomain.o: ${OBJECTDIR}/src/md5.o src/md5.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	@NMOUTPUT=`${NM} ${OBJECTDIR}/src/md5.o`; \
	if (echo "$$NMOUTPUT" | ${GREP} '|main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T _main$$'); \
	then  \
	    ${RM} "$@.d";\
	    $(COMPILE.cc) -O2 -fPIC  -Dmain=__nomain -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/md5_nomain.o src/md5.cpp;\
	else  \
	    ${CP} ${OBJECTDIR}/src/md5.o ${OBJECTDIR}/src/md5_nomain.o;\
	fi

${OBJECTDIR}/src/sha1_nomain.o: ${OBJECTDIR}/src/sha1.o src/sha1.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	@NMOUTPUT=`${NM} ${OBJECTDIR}/src/sha1.o`; \
	if (echo "$$NMOUTPUT" | ${GREP} '|main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T _main$$'); \
	then  \
	    ${RM} "$@.d";\
	    $(COMPILE.cc) -O2 -fPIC  -Dmain=__nomain -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/sha1_nomain.o src/sha1.cpp;\
	else  \
	    ${CP} ${OBJECTDIR}/src/sha1.o ${OBJECTDIR}/src/sha1_nomain.o;\
	fi

${OBJECTDIR}/src/sha2_nomain.o: ${OBJECTDIR}/src/sha2.o src/sha2.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	@NMOUTPUT=`${NM} ${OBJECTDIR}/src/sha2.o`; \
	if (echo "$$NMOUTPUT" | ${GREP} '|main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T main$$') || \
	   (echo "$$NMOUTPUT" | ${GREP} 'T _main$$'); \
	then  \
	    ${RM} "$@.d";\
	    $(COMPILE.cc) -O2 -fPIC  -Dmain=__nomain -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/sha2_nomain.o src/sha2.cpp;\
	else  \
	    ${CP} ${OBJECTDIR}/src/sha2.o ${OBJECTDIR}/src/sha2_nomain.o;\
	fi

# Run Test Targets
.test-conf:
	@if [ "${TEST}" = "" ]; \
	then  \
	    ${TESTDIR}/TestFiles/f2 || true; \
	else  \
	    ./${TEST} || true; \
	fi

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
