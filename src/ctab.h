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

#define CTAB_CHR	0x01
#define CTAB_UPALPHA	0x02
#define CTAB_LOALPHA	0x04
#define CTAB_ALPHA	(CTAB_UPALPHA | CTAB_LOALPHA)
#define CTAB_DIGIT	0x08
#define CTAB_CTL	0x10
#define CTAB_SEP	0x20
#define CTAB_HEX	0x40
#define CTAB_TOKEN	0x80

extern const unsigned char ctab[256];

#define CTAB_PTR(x)	(ctab[*(const unsigned char *)(x)])

#endif /* __CTAB_H */
