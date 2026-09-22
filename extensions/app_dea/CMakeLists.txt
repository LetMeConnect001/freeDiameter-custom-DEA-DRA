# The app_dea extension - Diameter Edge Agent (topology hiding)
PROJECT("Diameter Edge Agent extension" C)

# Parser files
BISON_FILE(dea_conf.y)
FLEX_FILE(dea_conf.l)
SET_SOURCE_FILES_PROPERTIES(lex.dea_conf.c dea_conf.tab.c PROPERTIES COMPILE_FLAGS "-I ${CMAKE_CURRENT_SOURCE_DIR}")

# List of source files
SET( APP_DEA_SRC
	app_dea.c
	app_dea.h
	lex.dea_conf.c
	dea_conf.tab.c
	dea_conf.tab.h
	dea_hiding.c
)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

# Compile these files as a freeDiameter extension
FD_ADD_EXTENSION(app_dea ${APP_DEA_SRC})


####
## INSTALL section ##

INSTALL(TARGETS app_dea
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT freeDiameter-app_dea)
