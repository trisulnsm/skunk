INCLUDES = $(all_includes)
METASOURCES = AUTO
bin_PROGRAMS = skunk
pkgdata_SCRIPTS = stskunk SkunkConfig.xml
AM_CXXFLAGS = -DLINUX_BUILD -DLINUX -DUSE_PFSENDER
skunk_LDADD = -lpcap  -lncurses
skunk_SOURCES = INetSender.cpp INetSender.h Impex_Libpcap.cpp Impex_Libpcap.h \
	PFSender.cpp PFSender.h PcapSender.cpp PcapSender.h SkunkApp.cpp SkunkApp.h \
	linuxdefs.h skunk.cpp skunk.h \
	MiscUtils.cpp MiscUtils.h TimeUtils.cpp TimeUtils.h \
	SafeStr.cpp SafeStr.h  xmlParser.cpp xmlParser.h 

noinst_HEADERS = stskunk SkunkConfig.xml
