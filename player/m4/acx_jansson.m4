AC_DEFUN([ACX_JANSSON],[
	AC_ARG_WITH(jansson, 
		[AC_HELP_STRING([--with-jansson=PATH],[specify prefix of path of jansson library to use])],
        	[
			JANSSON_PATH="$withval"
		],[
			JANSSON_PATH="/usr/local"
		])

    AC_MSG_CHECKING(what are the jansson includes)
    JANSSON_INCLUDES="-I$JANSSON_PATH/include"
    AC_MSG_RESULT($JANSSON_INCLUDES)

    AC_MSG_CHECKING(what are the jansson libs)
    JANSSON_LIBS="-L$JANSSON_PATH/lib -ljansson"
    AC_MSG_RESULT($JANSSON_LIBS)

	tmp_CFLAGS=$CFLAGS
	tmp_LIBS=$LIBS

	CFLAGS="$CFLAGS $JANSSON_INCLUDES"
	LIBS="$LIBS $JANSSON_LIBS"

    AC_CHECK_HEADERS(jansson.h,,[AC_MSG_ERROR([Can't find jansson headers])])
	AC_CHECK_LIB(jansson, json_loadf, [],[AC_MSG_ERROR([Can't find jansson library])])

    CFLAGS=$tmp_CFLAGS
    LIBS=$tmp_LIBS

	AC_SUBST(JANSSON_INCLUDES)
	AC_SUBST(JANSSON_LIBS)
])
