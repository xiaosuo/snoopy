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

extern const unsigned short ctab[256];

#define CTAB_PTR(x)	(ctab[*(const unsigned char *)(x)])

#endif /* __CTAB_H */
