/*
 * BinReloc - a library for creating relocatable executables
 * Written by: Hongli Lai <h.lai@chello.nl>
 * http://autopackage.org/
 *
 * This source code is public domain. You can relicense this code
 * under whatever license you want.
 *
 * See http://autopackage.org/docs/binreloc/ for
 * more information and how to use this.
 */

#ifndef __BINRELOC_H__
#define __BINRELOC_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef enum {
	/* Cannot allocate memory. */
	BR_FIND_EXE_NOMEM,
	/* Unable to open /proc/self/maps; see errno for details. */
	BR_FIND_EXE_OPEN_MAPS,
	/* Unable to read from /proc/self/maps; see errno for details. */
	BR_FIND_EXE_READ_MAPS,
	/* The file format of /proc/self/maps is invalid; kernel bug? */
	BR_FIND_EXE_INVALID_MAPS,
	/* BinReloc is disabled. */
	BR_FIND_EXE_DISABLED
} BrFindExeError;


/* Mangle symbol name to avoid symbol collision with other ELF objects. */
#define br_find_exe WwNM50677108521365_br_find_exe

char *br_find_exe (BrFindExeError *error);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __BINRELOC_H__ */
