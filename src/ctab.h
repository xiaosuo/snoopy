/**
 * Snoopy - A lightweight bypass censorship system for HTTP
 * Copyright (C) 2012- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CTAB_H
#define __CTAB_H

#include <stdbool.h>

#define CTAB_CHAR	0x0001
#define CTAB_UPALPHA	0x0002
#define CTAB_LOALPHA	0x0004
#define CTAB_ALPHA	(CTAB_UPALPHA | CTAB_LOALPHA)
#define CTAB_DIGIT	0x0008
#define CTAB_CTL	0x0010
#define CTAB_SEP	0x0020
#define CTAB_HEX	0x0040
#define CTAB_TOKEN	0x0080
#define CTAB_SPACE	0x0100
#define CTAB_LWS	0x0200
#define CTAB_TEXT	0x0400

extern const unsigned short ctab[256];

#define DEFINE_IS_X(suffix, type) \
static inline bool is_##suffix(unsigned char c) \
{ \
	return (ctab[c] & (type)) != 0; \
}

DEFINE_IS_X(char, CTAB_CHAR);
DEFINE_IS_X(upalpha, CTAB_UPALPHA);
DEFINE_IS_X(loalpha, CTAB_LOALPHA);
DEFINE_IS_X(alpha, CTAB_ALPHA);
DEFINE_IS_X(digit, CTAB_DIGIT);
DEFINE_IS_X(ctl, CTAB_CTL);
DEFINE_IS_X(sep, CTAB_SEP);
DEFINE_IS_X(hex, CTAB_HEX);
DEFINE_IS_X(token, CTAB_TOKEN);
DEFINE_IS_X(space, CTAB_SPACE);
DEFINE_IS_X(lws, CTAB_LWS);
DEFINE_IS_X(text, CTAB_TEXT);

#endif /* __CTAB_H */
