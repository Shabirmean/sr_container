/**
 *  @title      :   sr_container.c
 *  @author     :   Shabir Abdul Samadh (shabirmean@cs.mcgill.ca/shabir_tck@hotmail.com)
 *  @date       :   20th Nov 2018
 *  @purpose    :   COMP310/ECSE427 Operating Systems (Assingment 3) - Phase 2
 *  @description:   A template C code to be filled in order to spawn container instances
 *  @compilation:   Use "make container" with the given Makefile
 * ./SNR_CONTAINER -m srootfs -u 1 -H harry -C 212 -M 1024000 -p 50 -r "253:0 2048000" -w "253:0 2048000" -c /bin/bash
*/

#include "sr_container.h"

/**
 *  The cgroup setting to add the writing task to the cgroup
 *  '0' is considered a special value and writing it to 'tasks' asks for the wrinting 
 *      process to be added to the cgroup. 
 *  You must add this to all the controls you create so that it is added to the task list.
 *  See the example 'cgroups_control' added to the array of controls - 'cgroups' - below
 **/  
struct cgroup_setting self_to_task = {
	.name = "tasks",
	.value = "0"
};

/**
 *  ------------------------ TODO ------------------------
 *  An array of different cgroup-controllers.
 *  One controller has been been added for you.
 *  You should fill this array with the additional controls from commandline flags as described 
 *      in the comments for the main() below
 *  ------------------------------------------------------
 **/ 
struct cgroups_control *cgroups[6] = {
	& (struct cgroups_control) {
		.control = CGRP_BLKIO_CONTROL,
		.settings = (struct cgroup_setting *[]) {
			& (struct cgroup_setting) {
				.name = "blkio.weight",
				.value = "64"
			},
			&self_to_task,             // must be added to all the new controls added
			NULL                       // NULL at the end of the array
		}
	},
	NULL                               // NULL at the end of the array
};


/**
 *  ------------------------ TODO ------------------------
 *  The SRContainer by default suppoprts three flags:
 *          1. m : The rootfs of the container
 *          2. u : The userid mapping of the current user inside the container
 *          3. c : The initial process to run inside the container
 *  
 *   You must extend it to support the following flags:
 *          1. C : The cpu shares weight to be set (cpu-cgroup controller)
 *          2. s : The cpu cores to which the container must be restricted (cpuset-cgroup controller)
 *          3. p : The max number of process's allowed within a container (pid-cgroup controller)
 *          4. M : The memory consuption allowed in the container (memory-cgroup controller)
 *          5. r : The read IO rate in bytes (blkio-cgroup controller)
 *          6. w : The write IO rate in bytes (blkio-cgroup controller)
 *          7. H : The hostname of the container 
 * 
 *   You can follow the current method followed to take in these flags and extend it.
 *   Note that the current implementation necessitates the "-c" flag to be the last one.
 *   For flags 1-6 you can add a new 'cgroups_control' to the existing 'cgroups' array
 *   For 7 you have to just set the hostname parameter of the 'child_config' struct in the header file
 *  ------------------------------------------------------
 **/
int main(int argc, char **argv)
{
    struct child_config config = {0};
    int option = 0;
    int sockets[2] = {0};
    //pid_t child_pid = 0;
    int last_optind = 0;
    bool found_cflag = false;

    struct cgroups_control *cpu_control = calloc(1, sizeof(struct cgroups_control));
    struct cgroups_control *cpuset_control = calloc(1, sizeof(struct cgroups_control));
    struct cgroups_control *pids_control = calloc(1, sizeof(struct cgroups_control));
    struct cgroups_control *memory_control = calloc(1, sizeof(struct cgroups_control));
    struct cgroups_control *blkio_control = calloc(1, sizeof(struct cgroups_control));
    while ((option = getopt(argc, argv, "c:m:u:H:C:s:p:M:r:w:")))
    {
        int idx = 0;
        if (found_cflag)
            break;

        switch (option)
        {
        case 'c':
            config.argc = argc - last_optind - 1;
            config.argv = &argv[argc - config.argc];
            found_cflag = true;
            break;
        case 'm':
            config.mount_dir = optarg;
            break;
        case 'H':
            config.hostname = optarg;
            break;
        case 'u':
            if (sscanf(optarg, "%d", &config.uid) != 1)
            {
                fprintf(stderr, "UID not as expected: %s\n", optarg);
                cleanup_stuff(argv, sockets);
                return EXIT_FAILURE;
            }
            break;

        case 'C':
            strcpy(cpu_control->control, "cpu");
            cpu_control->settings = calloc(3, sizeof(struct cgroup_setting*));
            for (int i = 0; i < 3; i++) {
                cpu_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(cpu_control->settings[0]->name, "cpu.shares");
            strcpy(cpu_control->settings[0]->value, optarg);
            cpu_control->settings[1] = &self_to_task;
            cpu_control->settings[2] = NULL;

            while (cgroups[idx] != NULL) {
                idx++;
            }
            cgroups[idx] = cpu_control;
            cgroups[idx+1] = NULL;
            break;

        case 's':
            strcpy(cpuset_control->control, "cpuset");
            cpuset_control->settings = calloc(3, sizeof(struct cgroup_setting*));
            for (int i = 0; i < 4; i++) {
                cpuset_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(cpuset_control->settings[0]->name, "cpuset.cpus");
            strcpy(cpuset_control->settings[0]->value, optarg);
            strcpy(cpuset_control->settings[1]->name, "cpuset.mems");
            strcpy(cpuset_control->settings[1]->value, "0");
            cpuset_control->settings[2] = &self_to_task;
            cpuset_control->settings[3] = NULL;

            while (cgroups[idx] != NULL) {
                idx++;
            }
            cgroups[idx] = cpuset_control;
            cgroups[idx+1] = NULL;
            break;

        case 'p':
            strcpy(pids_control->control, "pids");
            pids_control->settings = calloc(3, sizeof(struct cgroup_setting*));
            for (int i = 0; i < 3; i++) {
                pids_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(pids_control->settings[0]->name, "pids.max");
            strcpy(pids_control->settings[0]->value, optarg);
            pids_control->settings[1] = &self_to_task;
            pids_control->settings[2] = NULL;

            while (cgroups[idx] != NULL) {
                idx++;
            }
            cgroups[idx] = pids_control;
            cgroups[idx+1] = NULL;
            break;

        case 'M':
            strcpy(memory_control->control, "memory");
            memory_control->settings = calloc(3, sizeof(struct cgroup_setting*));
            for (int i = 0; i < 4; i++) {
                memory_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(memory_control->settings[0]->name, "memory.limit_in_bytes");
            strcpy(memory_control->settings[0]->value, optarg);
            strcpy(memory_control->settings[1]->name, "memory.kmem.limit_in_bytes");
            strcpy(memory_control->settings[1]->value, optarg);
            memory_control->settings[2] = &self_to_task;
            memory_control->settings[3] = NULL;

            while (cgroups[idx] != NULL) {
                idx++;
            }
            cgroups[idx] = memory_control;
            cgroups[idx+1] = NULL;
            break;

        case 'r':
            if (strcmp(blkio_control->control, "blkio")) {
                strcpy(blkio_control->control, "blkio");
                blkio_control->settings = calloc(4, sizeof(struct cgroup_setting*));
                for (int i = 0; i < 4; i++) {
                    blkio_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
                }
                strcpy(blkio_control->settings[0]->name, cgroups[0]->settings[0]->name);
                strcpy(blkio_control->settings[0]->value, cgroups[0]->settings[0]->value);
                strcpy(blkio_control->settings[1]->name, "blkio.throttle.read_bps_device");
                strcpy(blkio_control->settings[1]->value, optarg);
                blkio_control->settings[2] = &self_to_task;
                blkio_control->settings[3] = NULL;
                
            } else {
                blkio_control->settings = realloc(blkio_control->settings, sizeof(struct cgroup_setting*) * 5);
                blkio_control->settings[3] = calloc(1, sizeof(struct cgroup_setting));
                blkio_control->settings[2] = calloc(1, sizeof(struct cgroup_setting));
                strcpy(blkio_control->settings[2]->name, "blkio.throttle.read_bps_device");
                strcpy(blkio_control->settings[2]->value, optarg);
                blkio_control->settings[3] = &self_to_task;
                blkio_control->settings[4] = NULL;
            }
            cgroups[0] = blkio_control;
            break;

        case 'w':
            if (strcmp(blkio_control->control, "blkio")) {
                strcpy(blkio_control->control, "blkio");
                blkio_control->settings = calloc(4, sizeof(struct cgroup_setting*));
                for (int i = 0; i < 4; i++) {
                    blkio_control->settings[i] = calloc(1, sizeof(struct cgroup_setting));
                }
                strcpy(blkio_control->settings[0]->name, cgroups[0]->settings[0]->name);
                strcpy(blkio_control->settings[0]->value, cgroups[0]->settings[0]->value);
                strcpy(blkio_control->settings[1]->name, "blkio.throttle.write_bps_device");
                strcpy(blkio_control->settings[1]->value, optarg);
                blkio_control->settings[2] = &self_to_task;
                blkio_control->settings[3] = NULL;
                
            } else {
                blkio_control->settings = realloc(blkio_control->settings, sizeof(struct cgroup_setting*) * 5);
                blkio_control->settings[3] = calloc(1, sizeof(struct cgroup_setting));
                blkio_control->settings[2] = calloc(1, sizeof(struct cgroup_setting));
                strcpy(blkio_control->settings[2]->name, "blkio.throttle.write_bps_device");
                strcpy(blkio_control->settings[2]->value, optarg);
                blkio_control->settings[3] = &self_to_task;
                blkio_control->settings[4] = NULL;
            }
            cgroups[0] = blkio_control;
            break;

        default:
            cleanup_stuff(argv, sockets);
            return EXIT_FAILURE;
        }
        last_optind = optind;
    }

    if (!config.argc || !config.mount_dir){
        cleanup_stuff(argv, sockets);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "==> Checking if the host Linux version is compatible...");
    struct utsname host = {0};
    if (uname(&host))
    {
        fprintf(stderr, "invocation to uname() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u.", &major, &minor) != 2)
    {
        fprintf(stderr, "major minor version is unknown: %s\n", host.release);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (major != 4 || (minor < 7))
    {
        fprintf(stderr, "Linux version must be 4.7.x or minor version less than 7: %s\n", host.release);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (strcmp(ARCH_TYPE, host.machine))
    {
        fprintf(stderr, "architecture must be x86_64: %s\n", host.machine);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets))
    {
        fprintf(stderr, "invocation to socketpair() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC))
    {
        fprintf(stderr, "invocation to fcntl() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    config.fd = sockets[1];

    /**
     * ------------------------ TODO ------------------------
     * This method here is creating the control groups using the 'cgroups' array
     * Make sure you have filled in this array with the correct values from the command line flags 
     * Nothing to write here, just caution to ensure the array is filled
     * ------------------------------------------------------
     **/
    if (setup_cgroup_controls(&config, cgroups))
    {
        clean_child_structures(&config, cgroups, NULL);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    
    /**
     * ------------------------ TODO ------------------------
     * Setup a stack and create a new child process using the clone() system call
     * Ensure you have correct flags for the following namespaces:
     *      Network, Cgroup, PID, IPC, Mount, UTS (You don't need to add user namespace)
     * Set the return value of clone to 'child_pid'
     * Ensure to add 'SIGCHLD' flag to the clone() call
     * You can use the 'child_function' given below as the function to run in the cloned process
     * HINT: Note that the 'child_function' expects struct of type child_config.
     * ------------------------------------------------------
     **/

    char *stack = 0;
	if (!(stack = malloc(STACK_SIZE))) {
		fprintf(stderr, "=> malloc failed, out of memory?\n");
        return EXIT_FAILURE;
	}
    
	int flags = CLONE_NEWNS
		| CLONE_NEWCGROUP
		| CLONE_NEWPID
		| CLONE_NEWIPC
		// | CLONE_NEWNET
		| CLONE_NEWUTS;

    fprintf(stderr, "successfully setup child mounts.\n");

	if ((config.child_pid = clone(child_function, stack + STACK_SIZE, flags | SIGCHLD, &config)) == -1) {
		fprintf(stderr, "=> clone failed! %m\n");
        return EXIT_FAILURE;
	}

    /**
     *  ------------------------------------------------------
     **/ 
    if (config.child_pid == -1)
    {
        fprintf(stderr, "==> child creation failed! %m\n");
        clean_child_structures(&config, cgroups, stack);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    close(sockets[1]);
    sockets[1] = 0;

    if (setup_child_uid_map(&config, sockets[0]))
    {
        if (config.child_pid)
            kill(config.child_pid, SIGKILL);
    }

    int child_status = 0;
    waitpid(config.child_pid, &child_status, 0);
    int exit_status = WEXITSTATUS(child_status);

    clean_child_structures(&config, cgroups, stack);
    cleanup_sockets(sockets);
    return exit_status;
}


int child_function(void *arg)
{
    struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname)) || \
                setup_child_mounts(config) || \
                setup_child_userns(config) || \
                setup_child_capabilities() || \
                setup_syscall_filters()
        )
    {
        close(config->fd);
        return -1;
    }
    if (close(config->fd))
    {
        fprintf(stderr, "invocation to close() failed: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL))
    {
        fprintf(stderr, "invocation to execve() failed! %m.\n");
        return -1;
    }
    return 0;
}
