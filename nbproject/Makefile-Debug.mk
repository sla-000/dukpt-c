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
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/dukpt/dukpt.o \
	${OBJECTDIR}/slog/slog.o \
	${OBJECTDIR}/src/main.o


# C Compiler Flags
CFLAGS=-Wextra -fno-strict-aliasing -std=gnu11

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-L/usr/lib/x86_64-linux-gnu -lpthread -lssl -lcrypto

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dukpt

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dukpt: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dukpt ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/dukpt/dukpt.o: dukpt/dukpt.c
	${MKDIR} -p ${OBJECTDIR}/dukpt
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall -DDEBUG -DDUKPT_TEST -Iinclude -I. -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/dukpt/dukpt.o dukpt/dukpt.c

${OBJECTDIR}/slog/slog.o: slog/slog.c
	${MKDIR} -p ${OBJECTDIR}/slog
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall -DDEBUG -DDUKPT_TEST -Iinclude -I. -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/slog/slog.o slog/slog.c

${OBJECTDIR}/src/main.o: src/main.c
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall -DDEBUG -DDUKPT_TEST -Iinclude -I. -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/main.o src/main.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
