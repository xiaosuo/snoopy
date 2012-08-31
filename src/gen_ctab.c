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

#include "ctab.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int i;
	int ctab[256];

	memset(ctab, 0, sizeof(ctab));
	for (i = 0; i < 256; i++) {
		/* CHAR           = <any US-ASCII character (octets 0 - 127)> */
		if (i <= 127)
			ctab[i] |= CTAB_CHR;
		/* UPALPHA        = <any US-ASCII uppercase letter "A".."Z"> */
		if (i >= 'A' && i <= 'Z')
			ctab[i] |= CTAB_UPALPHA;
		/* LOALPHA        = <any US-ASCII lowercase letter "a".."z"> */
		if (i >= 'a' && i <= 'z')
			ctab[i] |= CTAB_LOALPHA;
		/* DIGIT          = <any US-ASCII digit "0".."9"> */
		if (i >= '0' && i <= '9')
			ctab[i] |= CTAB_DIGIT;
		/**
		 * CTL            = <any US-ASCII control character
		 * 		  (octets 0 - 31) and DEL (127)>
		 */
		if (i <= 31 || i == 127)
			ctab[i] |= CTAB_CTL;
		/**
		 * HEX            = "A" | "B" | "C" | "D" | "E" | "F"
		 * 		  | "a" | "b" | "c" | "d" | "e" | "f" | DIGIT
		 */
		if ((i >= 'a' && i <= 'f') || (i >= 'A' && i <= 'F') ||
		    (ctab[i] & CTAB_DIGIT))
			ctab[i] |= CTAB_HEX;
		/**
		 * separators     = "(" | ")" | "<" | ">" | "@"
		 * 		  | "," | ";" | ":" | "\" | <">
		 * 		  | "/" | "[" | "]" | "?" | "="
		 * 		  | "{" | "}" | SP | HT
		 */
		if (i != 0 && strchr("()<>@,;:\\\"/[]?={} \t", i))
			ctab[i] |= CTAB_SEP;
		/* token          = 1*<any CHAR except CTLs or separators> */
		if ((ctab[i] & CTAB_CHR) && !(ctab[i] & (CTAB_CTL | CTAB_SEP)))
			ctab[i] |= CTAB_TOKEN;
	}

	printf("#include \"ctab.h\"\n");
	printf("\n");
	printf("const unsigned char ctab[256] = {\n");
	for (i = 0; i < 256 / 8; i++) {
		int j;

		printf("\t");
		for (j = 0; j < 8; j++)
			printf("0x%02x,%s", ctab[i * 8 + j], j != 7 ? " " : "");
		printf("\n");
	}
	printf("};\n");

	return 0;
}
