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

#include "pcap_list.h"
#include "list.h"
#include "utils.h"
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <net/ethernet.h>

struct pcap_entry {
	pcap_t				*p;
	stlist_entry(struct pcap_entry)	link;
	char				err_buf[PCAP_ERRBUF_SIZE];
	char				*name;
};

struct pcap_list {
	int					n_entries;
	stlist_head( , struct pcap_entry)	list;
	int					signo_fd[2];
	struct pcap_entry			*current_entry;
	struct pcap_entry			*error_entry;
	struct pollfd				*pollfd;
};

pcap_list_t *pcap_list_alloc(void)
{
	pcap_list_t *pl = malloc(sizeof(*pl));

	if (!pl)
		goto err;
	pl->n_entries = 0;
	stlist_head_init(&pl->list);
	if (pipe(pl->signo_fd) < 0)
		goto err2;
	if (set_nonblock(pl->signo_fd[0]) < 0 ||
	    set_nonblock(pl->signo_fd[1]) < 0)
		goto err3;
	pl->current_entry = NULL;
	pl->error_entry = NULL;
	pl->pollfd = NULL;

	return pl;
err3:
	close(pl->signo_fd[0]);
	close(pl->signo_fd[1]);
err2:
	free(pl);
err:
	return NULL;
}

int pcap_list_add(pcap_list_t *pl, const char *name)
{
	struct pcap_entry *e = malloc(sizeof(*e));

	if (!e)
		goto err;
	e->name = strdup(name);
	if (!e->name)
		goto err2;
	e->p = NULL;
	e->err_buf[0] = '\0';
	stlist_add_tail(&pl->list, e, link);
	pl->n_entries++;

	return 0;
err2:
	free(e);
err:
	return -1;
}

void pcap_list_free(pcap_list_t *pl)
{
	struct pcap_entry *e;

	while ((e = stlist_first(&pl->list))) {
		stlist_del_head(&pl->list, e, link);
		free(e->name);
		if (e->p)
			pcap_close(e->p);
		free(e);
	}
	free(pl->pollfd);
	close(pl->signo_fd[0]);
	close(pl->signo_fd[1]);
	free(pl);
}

void pcap_list_breakloop(pcap_list_t *pl)
{
	write(pl->signo_fd[1], "@", 1);
	if (pl->current_entry)
		pcap_breakloop(pl->current_entry->p);
}

const char *pcap_list_geterr(pcap_list_t *pl)
{
	if (pl->error_entry) {
		if (pl->error_entry->p)
			return pcap_geterr(pl->error_entry->p);
		else
			return pl->error_entry->err_buf;
	} else {
		return "";
	}
}

int pcap_list_stats(pcap_list_t *pl, struct pcap_stat *st)
{
	struct pcap_stat tmp;
	struct pcap_entry *e;

	st->ps_recv = 0;
	st->ps_drop = 0;
	stlist_for_each(e, &pl->list, link) {
		if (pcap_stats(e->p, &tmp)) {
			pl->error_entry = e;
			return -1;
		}
		st->ps_recv += tmp.ps_recv;
		st->ps_drop += tmp.ps_drop;
	}

	return 0;
}

int pcap_list_open_live(pcap_list_t *pl, int snap_len, int buf_size)
{
	struct pcap_entry *e;
	int fd;

	if (pl->n_entries == 0)
		goto err;

	stlist_for_each(e, &pl->list, link) {
		int my_snap_len = snap_len;

		if (!my_snap_len) {
			my_snap_len = if_get_mtu(e->name);
			if (my_snap_len < 0) {
				snprintf(e->err_buf, sizeof(e->err_buf),
					 "failed to get the MTU of %s",
					 e->name);
				goto err2;
			}
			my_snap_len += sizeof(struct ether_header) +
					sizeof(struct vlan_hdr);
		}
		e->err_buf[0] = '\0';
		e->p = pcap_create(e->name, e->err_buf);
		if (!e->p)
			goto err2;
		pcap_set_snaplen(e->p, my_snap_len);
		pcap_set_promisc(e->p, 1);
		pcap_set_timeout(e->p, 1);
		pcap_set_buffer_size(e->p, buf_size * 1024 * 1024);
		if (pcap_activate(e->p))
			goto err2;
		fd = pcap_get_selectable_fd(e->p);
		if (fd < 0)
			goto err2;
		if (set_nonblock(fd) < 0)
			goto err2;
	}

	return 0;
err2:
	pl->error_entry = e;
err:
	return -1;
}

int pcap_list_open_offline(pcap_list_t *pl, const char *fn)
{
	struct pcap_entry *e;

	if (pl->n_entries != 1)
		goto err;
	e = stlist_first(&pl->list);
	e->p = pcap_open_offline(fn, e->err_buf);
	if (!e->p)
		goto err2;

	return 0;
err2:
	pl->error_entry = e;
err:
	return -1;
}

int pcap_list_setfilter(pcap_list_t *pl, const char *str)
{
	struct pcap_entry *e;
	struct bpf_program fp;

	stlist_for_each(e, &pl->list, link) {
		if (pcap_compile(e->p, &fp, str, 1, 0))
			goto err;
		if (pcap_setfilter(e->p, &fp))
			goto err2;
		pcap_freecode(&fp);
	}

	return 0;
err2:
	pcap_freecode(&fp);
err:
	pl->error_entry = e;

	return -1;
}

int pcap_list_datalink(pcap_list_t *pl)
{
	struct pcap_entry *e;
	int dlt = -1;

	stlist_for_each(e, &pl->list, link) {
		if (dlt == -1)
			dlt = pcap_datalink(e->p);
		else if (dlt != pcap_datalink(e->p))
			return -1;
	}

	return dlt;
}

int pcap_list_loop(pcap_list_t *pl, pcap_handler callback, u_char *user)
{
	struct pcap_entry *e;

	if (!pl->pollfd) {
		struct pollfd *pf;

		pl->pollfd = calloc(pl->n_entries + 1, sizeof(*pl->pollfd));
		if (!pl->pollfd)
			goto err;
		pf = &pl->pollfd[0];
		stlist_for_each(e, &pl->list, link) {
			pf->fd = pcap_get_selectable_fd(e->p);
			pf->events = POLLIN;
			pf++;
		}
		pf->fd = pl->signo_fd[0];
		pf->events = POLLIN;
	}

	while (1) {
		struct pollfd *pf;
		bool got = false;
		int n = poll(pl->pollfd, pl->n_entries + 1, 1);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto err;
		} else if (n == 0) {
			continue;
		}

		pf = &pl->pollfd[0];
		stlist_for_each(e, &pl->list, link) {
			if (pf->revents != 0) {
				int ret;

				ret = pcap_dispatch(e->p, -1, callback, user);
				if (ret == -1) {
					pl->error_entry = e;
					goto err;
				} else if (ret > 0) {
					got = true;
				}
				if (--n == 0)
					break;
			}
			pf++;
		}
		if (n > 0) {
			char c = '\0';

			while (read(pl->signo_fd[0], &c, 1) == 1)
				/* nothing */;
			if (c == '@')
				break;
		} else if (!got) {
			break;
		}
	}

	return 0;
err:
	return -1;
}
