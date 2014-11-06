
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>

#define PROC_FILE_BUFFER_SIZE	4096

struct proc_uptime {
	double uptime;
	double idle;
};

struct proc_status {
	char state[4];
	unsigned int ppid;
	unsigned int pgid;
	unsigned int sid;
	int tty;
	unsigned long utime;
	unsigned long stime;
	unsigned long cutime;
	unsigned long cstime;
	long nice;
	double start_time;
	unsigned long vsz;
	unsigned long rss;
};

struct jiffy_counts {
	unsigned long long usr;
	unsigned long long nic;
	unsigned long long sys;
	unsigned long long idle;
	unsigned long long iowait;
	unsigned long long irq;
	unsigned long long softirq;
	unsigned long long steal;
	unsigned long long total;
	unsigned long long busy;
};

static double __gettimeofday (void)
{
	long long tsec;
	long long tusec;
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		return 0;
	}
	tsec = ((long long) ts.tv_sec) * 1000;
	tusec = ((long long) ts.tv_nsec) / 1000 / 1000;
	return (double) (tsec + tusec) / 1000.00;
}

static char * read_proc_file (const char *file)
{
	int fd;
	ssize_t rc;
	char *buffer;
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		printf("open failed for: %s\n", file);
		return NULL;
	}
	buffer = malloc(PROC_FILE_BUFFER_SIZE);
	if (buffer == NULL) {
		printf("malloc failed\n");
		close(fd);
		return NULL;
	}
	rc = read(fd, buffer, PROC_FILE_BUFFER_SIZE - 1);
	if (rc < 0) {
		printf("read failed\n");
		close(fd);
		free(buffer);
		return NULL;
	}
	buffer[rc] = '\0';
	close(fd);
	return buffer;
}

static int read_cpu_jiffy (FILE *fp, struct jiffy_counts *p_jif)
{
	int ret;
	char *buffer;
	static const char fmt[] = "cpu %llu %llu %llu %llu %llu %llu %llu %llu";

	buffer = malloc(PROC_FILE_BUFFER_SIZE);
	if (buffer == NULL) {
		printf("malloc failed\n");
		return -1;
	}

	if (!fgets(buffer, PROC_FILE_BUFFER_SIZE, fp) || buffer[0] != 'c' /* not "cpu" */) {
		free(buffer);
		return 0;
	}

	ret = sscanf(buffer, fmt,
			&p_jif->usr, &p_jif->nic, &p_jif->sys, &p_jif->idle,
			&p_jif->iowait, &p_jif->irq, &p_jif->softirq,
			&p_jif->steal);
	if (ret >= 4) {
		p_jif->total = p_jif->usr + p_jif->nic + p_jif->sys + p_jif->idle
			     + p_jif->iowait + p_jif->irq + p_jif->softirq + p_jif->steal;
		p_jif->busy = p_jif->total - p_jif->idle - p_jif->iowait;
	}

	free(buffer);
	return ret;
}

static inline int get_jiffy_counts (struct jiffy_counts *jiffy_counts)
{
	struct jiffy_counts cur_jif;
	FILE *fp = fopen("/proc/stat", "r");
	if (read_cpu_jiffy(fp, &cur_jif) < 4) {
		printf("can not read stat\n");
		fclose(fp);
		return -1;
	}
	*jiffy_counts = cur_jif;
	fclose(fp);
	return 0;
}

static inline int read_proc_uptime (struct proc_uptime *proc_uptime)
{
	int n;
	char *fname;
	char *buffer;

	fname = malloc(PATH_MAX);
	if (fname == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	snprintf(fname, PATH_MAX, "/proc/uptime");
	buffer = read_proc_file(fname);
	if (buffer == NULL) {
		printf("read proc file: %s failed\n", fname);
		free(fname);
		return -1;
	}
	free(fname);

	n = sscanf(buffer,
			"%lf %lf",
			&proc_uptime->uptime,
			&proc_uptime->idle
			);
	if (n != 2) {
		printf("read uptime failed\n");
		free(buffer);
		return -1;
	}

	free(buffer);
	return 0;
}

static int read_proc_stat (pid_t pid, struct proc_status *proc_status)
{
	int n;
	char *cp;
	char *fname;
	char *buffer;
	unsigned long ticks;
	unsigned long start_time;
	unsigned char shift_pages_to_kb;
	unsigned char shift_pages_to_bytes;

	n = getpagesize();
	shift_pages_to_bytes = 0;
	while (1) {
		n >>= 1;
		if (!n) {
			break;
		}
		shift_pages_to_bytes++;
	}
	shift_pages_to_kb = shift_pages_to_bytes - 10;

	fname = malloc(PATH_MAX);
	if (fname == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	snprintf(fname, PATH_MAX, "/proc/%d/stat", pid);
	buffer = read_proc_file(fname);
	if (buffer == NULL) {
		printf("read proc file: %s failed\n", fname);
		free(fname);
		return -1;
	}
	free(fname);

	cp = strrchr(buffer, ')');
	cp[0] = '\0';
        n = sscanf(cp + 2,
        		"%c %u "               /* state, ppid */
        		"%u %u %d %*s "        /* pgid, sid, tty, tpgid */
        		"%*s %*s %*s %*s %*s " /* flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
        		"%lu %lu "             /* utime, stime */
        		"%lu %lu %*s "         /* cutime, cstime, priority */
        		"%ld "                 /* nice */
        		"%*s %*s "             /* timeout, it_real_value */
        		"%lu "                 /* start_time */
        		"%lu "                 /* vsize */
        		"%lu "                 /* rss */
        		,
        		proc_status->state, &proc_status->ppid,
        		&proc_status->pgid, &proc_status->sid, &proc_status->tty,
        		&proc_status->utime, &proc_status->stime,
        		&proc_status->cutime, &proc_status->cstime,
        		&proc_status->nice,
        		&start_time,
        		&proc_status->vsz,
        		&proc_status->rss
                 	 );
        if (n < 11) {
        	printf("bogus stat data\n");
        	free(buffer);
        	return -1;
        }
        ticks = sysconf(_SC_CLK_TCK);
        proc_status->start_time = (double) start_time / ticks;
        proc_status->vsz >>= 10;
        proc_status->rss <<= shift_pages_to_kb;

	free(buffer);
	return 0;
}

static int command_execute (char **argv, unsigned int interval, const char *output)
{
	int i;
	int rc;
	FILE *fp;
	pid_t pid;
	int status;
	char *fname;
	double cpu_usage;
	double running_time;
	double total_time[4];
	struct proc_status proc_status;
	struct proc_uptime proc_uptime;
	struct jiffy_counts jiffy_counts;

	if ((pid = fork()) < 0) {
		printf("fork failed\n");
		return -1;
	} else if (pid == 0) {
		if (execvp(*argv, argv) < 0) {
			printf("exec failed\n");
			return -1;
		}
	} else {
		if (output != NULL) {
			fname = strdup(output);
			if (fname == NULL) {
				return -1;
			}
		} else {
			fname = malloc(PATH_MAX);
			if (fname == NULL) {
				return -1;
			}
			snprintf(fname, PATH_MAX, "histogram.%d", pid);
		}
		fp = fopen(fname, "w");
		if (fp == NULL) {
			printf("can not open file: %s", fname);
			free(fname);
			return -1;
		}
		fprintf(fp, "pid: %d\n", pid);
		fprintf(fp, "command:");
		for (i = 0; argv[i] != NULL; i++) {
			fprintf(fp, " %s", argv[i]);
		}
		fprintf(fp, "\n");
		fprintf(fp, "%s, %s, %s\n", "\"time (seconds)\"", "\"memory (kilobytes)\"", "\"cpu (%percent)\"");
		fclose(fp);

		total_time[0] = 0;
		total_time[1] = 0;
		total_time[2] = 0;
		total_time[3] = 0;
		total_time[4] = 0;
		total_time[5] = 0;
		do {
			rc = read_proc_uptime(&proc_uptime);
			if (rc != 0) {
				printf("read proc uptime failed\n");
				continue;
			}
			rc = read_proc_stat(pid, &proc_status);
			if (rc != 0) {
				printf("read proc stat failed\n");
				continue;
			}
		        rc = get_jiffy_counts(&jiffy_counts);
		        if (rc != 0) {
		        	printf("could not read jiffies\n");
		        	continue;
		        }
			total_time[1]  = proc_status.utime + proc_status.stime;
			total_time[1] += proc_status.cutime + proc_status.cstime;
			total_time[3] = __gettimeofday();
			running_time = total_time[3] - proc_status.start_time;
			cpu_usage = ((double) (total_time[1] - total_time[0]) / (double) (total_time[3] - total_time[2])) / sysconf(_SC_CLK_TCK) * 100.00;
			fp = fopen(fname, "a");
			if (fp == NULL) {
				printf("can not open file: %s", output);
				return -1;
			}
			fprintf(fp, "%16f, %20lu, %16f\n", running_time, proc_status.vsz, cpu_usage);
			fclose(fp);
			total_time[0] = total_time[1];
			total_time[2] = __gettimeofday();
			usleep(interval * 1000);
		} while (waitpid(pid, &status, WNOHANG) != pid);
		free(fname);
	}
	return 0;
}

static char * command_strip (char *buf)
{
	char *start;

	if (buf == NULL) {
		return NULL;
	}

	while ((*buf != '\0') && (buf[strlen(buf) - 1] < 33)) {
		buf[strlen(buf) - 1] = '\0';
	}

	start = buf;
	while (*start && (*start < 33)) {
		start++;
	}

	return start;
}

static int command_parse (const char *command, int *argc, char ***argv)
{
	char *b;
	char *p;
	int _argc;
	char **_argv;

	b = NULL;
	_argc = 0;
	_argv = NULL;
	b = strdup(command);
	p = b;

	_argv = (char **) realloc(_argv, sizeof(char *) * (_argc + 1));
	if (_argv == NULL) {
		goto error;
	}

	while (*p) {
		while (isspace(*p)) {
			p++;
		}

		if (*p == '"' || *p == '\'') {
			char const delim = *p;
			char *const begin = ++p;

			while (*p && *p != delim) {
				p++;
			}
			if (*p) {
				*p++ = '\0';
				_argv = (char **) realloc(_argv, sizeof(char *) * (_argc + 2));
				_argv[_argc] = strdup(command_strip(begin));
				_argc++;
			} else {
				goto error;
			}
		} else {
			char *const begin = p;

			while (*p && !isspace(*p)) {
				p++;
			}
			if (*p) {
				*p++ = '\0';
				_argv = (char **) realloc(_argv, sizeof(char *) * (_argc + 2));
				_argv[_argc] = strdup(command_strip(begin));
				_argc++;
			} else if (p != begin) {
				_argv = (char **) realloc(_argv, sizeof(char *) * (_argc + 2));
				_argv[_argc] = strdup(command_strip(begin));
				_argc++;
			}
		}
	}
	_argv[_argc] = NULL;

	*argc = _argc;
	*argv = _argv;
	free(b);
	return 0;

error:
	free(_argv);
	free(b);
	return -1;
}

static int print_help (const char *pname)
{
	printf("%s usage:\n", pname);
	printf("  -c : execute command\n");
	printf("  -o : output file (default: histogram.pid)\n");
	printf("  -i : interval in milicesonds (default: 1000)\n");
	printf("  -h : this text\n");
	return 0;
}

int main (int argc, char *argv[])
{
	int i;
	int c;
	int rc;
	int command_argc;
	char **command_argv;
	const char *output;
	const char *command;
	unsigned int interval;

	output = NULL;
	command = NULL;
	interval = 1000;

	while ((c = getopt(argc, argv, "hc:o:i:")) != -1) {
		switch (c) {
			case 'i':
				interval = atoi(optarg);
				break;
			case 'c':
				command = optarg;
				break;
			case 'o':
				output = optarg;
				break;
			case 'h':
				print_help(argv[0]);
				return 0;
			default:
				print_help(argv[0]);
				return -1;
		}
	}

	if (command == NULL) {
		print_help(argv[0]);
		return -1;
	}

	rc = command_parse(command, &command_argc, &command_argv);
	if (rc != 0) {
		printf("command parse failed\n");
		return -1;
	}

	rc = command_execute(command_argv, interval, output);
	if (rc != 0) {
		printf("command execute failed\n");
		return -1;
	}

	for (i = 0; i < command_argc; i++) {
		free(command_argv[i]);
	}
	free(command_argv);
	return 0;
}
