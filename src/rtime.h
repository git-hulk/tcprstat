/**
 *   rtime -- Extract stats about TCP response times
 *   Copyright (C) 2010  Ignacio Nin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/

#if !defined(RTIME_H)
#define RTIME_H

#define DEFAULT_OUTPUT_FORMAT "%n %a\\n"
#define DEFAULT_OUTPUT_INTERVAL 3
#define DEFAULT_OUTPUT_INTERVAL_STR "3"
#define MAX_OUTPUT_INTERVAL 60 * 60 * 24

extern int port;

void terminate(int signal);

#endif