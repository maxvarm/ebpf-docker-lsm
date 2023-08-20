struct meta_docker
{
    char id[12];
    char name[32];
    char image[32];
};

struct event_proc
{
    char allowed;
    struct meta_docker docker;
    unsigned int uid;
    unsigned int pid;
    unsigned int ppid;
    char path[64];
};

struct event_net
{
    char allowed;
    struct meta_docker docker;
    unsigned int uid;
    unsigned int pid;
    unsigned int ppid;
    unsigned int dport;
    char dip[16];
    char tp[4];
};