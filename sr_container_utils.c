/**
 *  @title      :   sr_container_utils.c
 *  @author     :   Shabir Abdul Samadh (shabirmean@cs.mcgill.ca)
 *  @purpose    :   COMP310/ECSE427 Operating Systems (Assingment 3) - Phase 2
 *  @description:   Utiity file for the SRContainer. No changes required to this file
*/
#include "sr_container.h"


void clean_child_structures(struct child_config *config, struct cgroups_control **cgrps, char *child_stack){
    free_cgroup_controls(config, cgrps);
    free(child_stack);
    delete_child_netns(config);
}

void cleanup_stuff(char *argv[], int sockets[2]) {
    print_usage(argv);
    cleanup_sockets(sockets);
}

void print_usage(char *argv[]){
    fprintf(stderr, "SRContainer usage: %s -u 1 -m . -c <process[eg:/bin/bash]>\n", argv[0]);
}

void cleanup_sockets(int sockets[2]) {
    if (sockets[0]) {
        close(sockets[0]);
    }

	if (sockets[1]) {
        close(sockets[1]);
    }
}

void delete_child_netns(struct child_config *config){
    const char *name;
	char netns_path[MAXPATHLEN];
    const char* netns_name = config->hostname;
	snprintf(netns_path, sizeof(netns_path), "%s/%s", NETNS_RUN_DIR, netns_name);
	umount2(netns_path, MNT_DETACH);
	if (unlink(netns_path) < 0) {
		fprintf(stderr, "Cannot remove %s: %s\n", netns_path, strerror(errno));
	}
}