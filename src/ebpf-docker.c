#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/inotify.h>
#include "structs.h"
#include "utils.h"
#include "ebpf-docker.skel.h"

#define CMD_LIST_CGROUP "ls -id /sys/fs/cgroup/system.slice/docker-* 2>/dev/null | sort -k 2"
#define CMD_LIST_DOCKER "docker container ls --format '{{.ID}} {{.Names}} {{.Image}}' | sort -k 1"

#define LOG_PROC_FORMAT \
    "%s type=process allowed=%i uid=%u pid=%u ppid=%u path=%s docker.id=%s docker.name=%s docker.image=%s\n"
#define LOG_NET_FORMAT \
    "%s type=network allowed=%i uid=%u pid=%u ppid=%u tp=%s dip=%s dport=%u docker.id=%s docker.name=%s docker.image=%s\n"

#define PATH_DEBUGPIPE "/sys/kernel/debug/tracing/trace_pipe"
#define PATH_CGROUPS "/sys/fs/cgroup/system.slice"
#define PATH_LOGFILE "./ebpf-docker.log"

/*
1. Delete all existing hashmap elements
2. List existing docker cgroups via ls -id
3. List existing, active docker containers
4. Map cgroups to containers via container ID
5. Fill the hashmap as <cgroup ID>: <docker context>
*/
void callback_inotify(struct bpf_map *map)
{
    // Race condition
    // Docker container list is updated only after 1-2 seconds
    sleep(1);

    // Utilize OS shell, seems to be much simpler to implement
    FILE *fcgroup, *fdocker;
    char rowcgroup[1256] = {}, rowdocker[1256] = {};
    fcgroup = popen(CMD_LIST_CGROUP, "r");
    fdocker = popen(CMD_LIST_DOCKER, "r");

    // Clear all hashmap elements, simpler than tracking every change
    unsigned long prev_k = 0, new_k = 0;
    struct meta_docker v = {};
    while (bpf_map__get_next_key(map, &prev_k, &new_k, sizeof(new_k)) == 0)
    {
        bpf_map__lookup_and_delete_elem(map, &new_k, sizeof(new_k), &v, sizeof(v), 0);
        prev_k = new_k;
    }

    // Fill the hashmap with new elements by parsing OS shell results
    while (fgets(rowcgroup, sizeof(rowcgroup), fcgroup) != NULL)
    {
        fgets(rowdocker, sizeof(rowdocker), fdocker);
        rowcgroup[strcspn(rowcgroup, "\n")] = 0;
        rowdocker[strcspn(rowdocker, "\n")] = 0;

        char *ptr = NULL;
        char *inode = strtok_r(rowcgroup, " ", &ptr);

        // Hashmap key is cgroup ID (inode number of container's cgroup folder)
        unsigned long key = strtoul(inode, &ptr, 10);

        // Hashmap value is docker context of container ID, name, and image
        ptr = NULL;
        struct meta_docker docker = {};
        strncpy(docker.id, strtok_r(rowdocker, " ", &ptr), sizeof(docker.id) - 1);
        strncpy(docker.name, strtok_r(ptr, " ", &ptr), sizeof(docker.name) - 1);
        strncpy(docker.image, strtok_r(ptr, " ", &ptr), sizeof(docker.image) - 1);
        // printf("%s, %s, %s, %s\n", inode, docker.id, docker.name, docker.image);

        bpf_map__update_elem(map, &key, sizeof(key), &docker, sizeof(docker), BPF_ANY);
    }
}

/*
1. Log received process event into the defined log file
*/
int callback_process(void *ctx, void *data, size_t data_sz)
{
    const struct event_proc *e = data;
    FILE *fout = (FILE *)ctx;
    time_t t = time(NULL);
    char eventtime[64];
    strftime(eventtime, sizeof(eventtime), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(fout, LOG_PROC_FORMAT, eventtime, e->allowed, e->uid, e->pid, e->ppid,
            e->path, e->docker.id, e->docker.name, e->docker.image);
    fflush(fout);
    return 0;
}

/*
1. Log received network event into the defined log file
*/
int callback_network(void *ctx, void *data, size_t data_sz)
{
    const struct event_net *e = data;
    FILE *fout = (FILE *)ctx;
    time_t t = time(NULL);
    char eventtime[64];
    strftime(eventtime, sizeof(eventtime), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(fout, LOG_NET_FORMAT, eventtime, e->allowed, e->uid, e->pid, e->ppid,
            e->tp, e->dip, e->dport, e->docker.id, e->docker.name, e->docker.image);
    fflush(fout);
    return 0;
}

/*
1. Open local log file to store events
2. Open kernel debug tracing pipe (Opt.)
3. Open ring buffers for each event type
4. Init inotify, watch for new docker cgroups
5.1. Start a single infinite loop
5.2. Poll for new events from eBPF
5.3. Poll for inotify folder changes
5.4. Handle new events or changes
*/
int startup(struct ebpf_docker_bpf *skel)
{
    FILE *fd_log;
    int fd_debug, fd_inotify;
    struct ring_buffer *rb_process;
    struct ring_buffer *rb_network;

    // Open local file to store event logs
    fd_log = fopen(PATH_LOGFILE, "a");

    // Open debug pipe to catch bpf_printk messages
    fd_debug = open(PATH_DEBUGPIPE, O_RDONLY);
    fcntl(fd_debug, F_SETFL, O_NONBLOCK);

    // Open ring buffer for each event type, put logfile descriptor as callback context
    rb_process = ring_buffer__new(bpf_map__fd(skel->maps.rb_process), callback_process, fd_log, NULL);
    rb_network = ring_buffer__new(bpf_map__fd(skel->maps.rb_network), callback_network, fd_log, NULL);

    // Init inotify, make read non-blocking
    fd_inotify = inotify_init();
    fcntl(fd_inotify, F_SETFL, O_NONBLOCK);
    inotify_add_watch(fd_inotify, PATH_CGROUPS, IN_CREATE | IN_DELETE | IN_ISDIR);

    // Fill initial cgroups hashmap
    callback_inotify(skel->maps.map_cgroups);

    while (!STOP)
    {
        int length, i = 0;
        // Poll for debug messages
        static char buff_debug[2048];
        length = read(fd_debug, buff_debug, sizeof(buff_debug));
        if (length > 0)
        {
            write(STDERR_FILENO, buff_debug, length);
        }

        // Poll for ring buffer events
        ring_buffer__poll(rb_process, 100);
        ring_buffer__poll(rb_network, 100);

        // Poll for inotify changes
        static char buff_inotify[2048];
        length = read(fd_inotify, buff_inotify, sizeof(buff_inotify));
        while (i < length)
        {
            // If changed dir starts with docker-*
            struct inotify_event *event = (struct inotify_event *)&buff_inotify[i];
            if (event->len && strncmp(event->name, "docker-", 7) == 0)
            {
                // Handle cgroups change, update cgroups hashmap
                callback_inotify(skel->maps.map_cgroups);
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }
    close(fd_debug);
    close(fd_inotify);
    fclose(fd_log);
    return 0;
}

int main(int argc, char **argv)
{
    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    if (signal(SIGINT, sigint) == SIG_ERR || signal(SIGTERM, sigint) == SIG_ERR)
    {
        goto cleanup;
    }

    // Open BPF skeleton
    struct ebpf_docker_bpf *skel = ebpf_docker_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load BPF skeleton
    int err = ebpf_docker_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // Attach BPF skeleton
    err = ebpf_docker_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Start main loop
    err = startup(skel);

cleanup:
    ebpf_docker_bpf__destroy(skel);
    return err;
}