/* SPDX-License-Identifier: Apache-2.0 */

/* Some support macros for doubly linked lists.
 *
 * Copyright 2008 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany.
 */
#ifndef DBLLINKLIST_H_INCLUDED
#define	DBLLINKLIST_H_INCLUDED

/* DLL means "doubly linked list". A class utilizing this macros
 * must define a pNext and pPrev pointer inside the list elements and
 * it must also define a root and last pointer. Please note that the
 * macros are NOT thread-safe. If you intend to use them in a threaed
 * environment, you must use proper synchronization.
 * NOTE: the caller must free the unlinked object, this is NOT done
 * in the macro!
 */
#define DLL_Del(pThis, pRoot, pLast) \
	if(pThis->pPrev != NULL) \
		pThis->pPrev->pNext = pThis->pNext; \
	if(pThis->pNext != NULL) \
		pThis->pNext->pPrev = pThis->pPrev; \
	if(pThis == pRoot) \
		pRoot = pThis->pNext; \
	if(pThis == pLast) \
		pLast = pThis->pPrev;

/* elements are always added to the tail of the list */
#define DLL_Add(pThis, pRoot, pLast) \
		if(pRoot == NULL) { \
			pRoot = pThis; \
			pLast = pThis; \
		} else { \
			pThis->pPrev = pLast; \
			pLast->pNext = pThis; \
			pLast = pThis; \
		}

#endif /* #ifndef DBLLINKLIST_H_INCLUDED */
