/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

int32_t lua_dofile (void)
{
	lua_State *L = luaL_newstate();
	luaL_openlibs(L);

	/* load script */
	luaL_dofile(L, "main.lua");
	/* call luaConn() provided by script */
	lua_getglobal(L, "luaConn");
	lua_call(L, 0, 1);
	printf("The luaConn is %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);

	//
	lua_close(L);
#if 0
	/* load script */
	luaL_dofile(L, "mood.lua");
	/* call mood() provided by script */
	lua_getglobal(L, "mood");
	lua_pushboolean(L, 1);
	lua_pushstring(L, "test string");
	lua_call(L, 2, 1);
	/* print the mood */
	printf("The mood is %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);

	//
	lua_getglobal(L, "mood");
	lua_pushnumber(L, 20);
	lua_pushnumber(L, 10);
	lua_call(L, 2, 1);
	/* print the mood */
	printf("The mood is %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);

	//
	lua_getglobal(L, "read_file");
	lua_call(L, 0, 1);
	printf("read_file is ...\n");
	printf("%s\n", lua_tostring(L, -1));

	// //
	// lua_close(L);
#endif

	return 0;
}
