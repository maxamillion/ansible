#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: podman_container

short_description: manage podman containers

description:
  - Manage the life cycle of podman containers.
  - Supports check mode. Run with --check and --diff to view config difference and list of actions to be taken.

version_added: "2.8"

options:
  auto_remove:
    description:
      - enable auto-removal of the container when the container's process exits
    type: bool
    default: 'no'
  blkio_weight:
    description:
      - Block IO (relative weight), between 10 and 1000.
  capabilities:
    description:
      - List of capabilities to add to the container.
  cap_drop:
    description:
      - List of capabilities to drop from the container.
  cleanup:
    description:
      - Use with I(detach=false) to remove the container after successful execution.
    type: bool
    default: 'no'
  command:
    description:
      - Command to execute when the container starts.
        A command may be either a string or a list.
  cpu_period:
    description:
      - Limit CPU CFS (Completely Fair Scheduler) period
  cpu_quota:
    description:
      - Limit CPU CFS (Completely Fair Scheduler) quota
  cpuset_cpus:
    description:
      - CPUs in which to allow execution C(1,3) or C(1-3).
  cpuset_mems:
    description:
      - Memory nodes (MEMs) in which to allow execution C(0-3) or C(0,1)
  cpu_shares:
    description:
      - CPU shares (relative weight).
  detach:
    description:
      - Enable detached mode to leave the container running in background.
        If disabled, the task will reflect the status of the container run (failed if the command failed).
    type: bool
    default: true
  devices:
    description:
      - "List of host device bindings to add to the container. Each binding is a mapping expressed
        in the format: <path_on_host>:<path_in_container>:<cgroup_permissions>"
  device_read_bps:
    description:
      - "List of device path and read rate (bytes per second) from device."
    type: list
    suboptions:
      path:
        type: str
        required: true
        description:
        - Device path in the container.
      rate:
        type: str
        required: true
        description:
        - "Device read limit. Format: <number>[<unit>]"
        - "Number is a positive integer. Unit can be one of C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
          C(T) (tebibyte), or C(P) (pebibyte)"
        - "Omitting the unit defaults to bytes."
  device_write_bps:
    description:
      - "List of device and write rate (bytes per second) to device."
    type: list
    suboptions:
      path:
        type: str
        required: true
        description:
        - Device path in the container.
      rate:
        type: str
        required: true
        description:
        - "Device read limit. Format: <number>[<unit>]"
        - "Number is a positive integer. Unit can be one of C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
          C(T) (tebibyte), or C(P) (pebibyte)"
        - "Omitting the unit defaults to bytes."
  device_read_iops:
    description:
      - "List of device and read rate (IO per second) from device."
    type: list
    suboptions:
      path:
        type: str
        required: true
        description:
        - Device path in the container.
      rate:
        type: int
        required: true
        description:
        - "Device read limit."
        - "Must be a positive integer."
  device_write_iops:
    description:
      - "List of device and write rate (IO per second) to device."
    type: list
    suboptions:
      path:
        type: str
        required: true
        description:
        - Device path in the container.
      rate:
        type: int
        required: true
        description:
        - "Device read limit."
        - "Must be a positive integer."
  dns_opts:
    description:
      - list of DNS options
  dns_servers:
    description:
      - List of custom DNS servers.
  dns_search_domains:
    description:
      - List of custom DNS search domains.
  domainname:
    description:
      - Container domainname.
  env:
    description:
      - Dictionary of key,value pairs.
      - Values which might be parsed as numbers, booleans or other types by the YAML parser must be quoted (e.g. C("true")) in order to avoid data loss.
    type: dict
  env_file:
    description:
      - Path to a file, present on the target, containing environment variables I(FOO=BAR).
      - If variable also present in C(env), then C(env) value will override.
  entrypoint:
    description:
      - Command that overwrites the default ENTRYPOINT of the image.
  etc_hosts:
    description:
      - Dict of host-to-IP mappings, where each host name is a key in the dictionary.
        Each host name will be added to the container's /etc/hosts file.
  exposed_ports:
    description:
      - List of additional container ports which informs Docker that the container
        listens on the specified network ports at runtime.
        If the port is already exposed using EXPOSE in a Dockerfile, it does not
        need to be exposed again.
    aliases:
      - exposed
      - expose
  force_kill:
    description:
      - Use the kill command when stopping a running container.
    type: bool
    default: 'no'
    aliases:
      - forcekill
  groups:
    description:
      - List of additional group names and/or IDs that the container process will run as.
  hostname:
    description:
      - Container hostname.
  image:
    description:
      - Repository path and tag used to create the container. If an image is not found or pull is true, the image
        will be pulled from the registry. If no tag is included, C(latest) will be used.
      - Can also be an image ID. If this is the case, the image is assumed to be available locally.
        The C(pull) option is ignored for this case.
  init:
    description:
      - Run an init inside the container that forwards signals and reaps processes.
        This option requires Docker API 1.25+.
    type: bool
    default: 'no'
  interactive:
    description:
      - Keep stdin open after a container is launched, even if not attached.
    type: bool
    default: 'no'
  ipc_mode:
    description:
      - Set the IPC mode for the container. Can be one of 'container:<name|id>' to reuse another
        container's IPC namespace or 'host' to use the host's IPC namespace within the container.
  keep_volumes:
    description:
      - Retain volumes associated with a removed container.
    type: bool
    default: 'yes'
  kill_signal:
    description:
      - Override default signal used to kill a running container.
  kernel_memory:
    description:
      - "Kernel memory limit (format: C(<number>[<unit>])). Number is a positive integer.
        Unit can be C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
        C(T) (tebibyte), or C(P) (pebibyte). Minimum is C(4M)."
      - Omitting the unit defaults to bytes.
  labels:
     description:
       - Dictionary of key value pairs.
  links:
    description:
      - List of name aliases for linked containers in the format C(container_name:alias).
      - Setting this will force container to be restarted.
  log_driver:
    description:
      - Specify the logging driver. Docker uses I(json-file) by default.
      - See L(here,https://docs.docker.com/config/containers/logging/configure/) for possible choices.
    required: false
  log_options:
    description:
      - Dictionary of options specific to the chosen log_driver. See https://docs.docker.com/engine/admin/logging/overview/
        for details.
    aliases:
      - log_opt
  mac_address:
    description:
      - Container MAC address (e.g. 92:d0:c6:0a:29:33)
  memory:
    description:
      - "Memory limit (format: C(<number>[<unit>])). Number is a positive integer.
        Unit can be C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
        C(T) (tebibyte), or C(P) (pebibyte)."
      - Omitting the unit defaults to bytes.
    default: '0'
  memory_reservation:
    description:
      - "Memory soft limit (format: C(<number>[<unit>])). Number is a positive integer.
        Unit can be C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
        C(T) (tebibyte), or C(P) (pebibyte)."
      - Omitting the unit defaults to bytes.
  memory_swap:
    description:
      - "Total memory limit (memory + swap, format: C(<number>[<unit>])).
        Number is a positive integer. Unit can be C(B) (byte), C(K) (kibibyte, 1024B),
        C(M) (mebibyte), C(G) (gibibyte), C(T) (tebibyte), or C(P) (pebibyte)."
      - Omitting the unit defaults to bytes.
  memory_swappiness:
    description:
        - Tune a container's memory swappiness behavior. Accepts an integer between 0 and 100.
        - If not set, the value will be remain the same if container exists and will be inherited from the host machine if it is (re-)created.
  name:
    description:
      - Assign a name to a new container or match an existing container.
      - When identifying an existing container name may be a name or a long or short container ID.
    required: true
  network_mode:
    description:
      - Connect the container to a network. Choices are "bridge", "host", "none" or "container:<name|id>"
  userns_mode:
     description:
       - User namespace to use
  networks:
     description:
       - List of networks the container belongs to.
       - For examples of the data structure and usage see EXAMPLES below.
       - To remove a container from one or more networks, use the C(purge_networks) option.
       - Note that as opposed to C(docker run ...), M(podman_container) does not remove the default
         network if C(networks) is specified. You need to explicity use C(purge_networks) to enforce
         the removal of the default network (and all other networks not explicitly mentioned in C(networks)).
     type: list
     suboptions:
        name:
           type: str
           required: true
           description:
             - The network's name.
        ipv4_address:
           type: str
           description:
             - The container's IPv4 address in this network.
        ipv6_address:
           type: str
           description:
             - The container's IPv6 address in this network.
        links:
           type: list
           description:
             - A list of containers to link to.
        aliases:
           type: list
           description:
             - List of aliases for this container in this network. These names
               can be used in the network to reach this container.
  oom_killer:
    description:
      - Whether or not to disable OOM Killer for the container.
    type: bool
  oom_score_adj:
    description:
      - An integer value containing the score given to the container in order to tune OOM killer preferences.
  output_logs:
    description:
      - If set to true, output of the container command will be printed (only effective when log_driver is set to json-file or journald.
    type: bool
    default: 'no'
  paused:
    description:
      - Use with the started state to pause running processes inside the container.
    type: bool
    default: 'no'
  pid_mode:
    description:
      - Set the PID namespace mode for the container.
  pids_limit:
    description:
      - Set PIDs limit for the container. It accepts an integer value.
      - Set -1 for unlimited PIDs.
    type: int
  privileged:
    description:
      - Give extended privileges to the container.
    type: bool
    default: 'no'
  published_ports:
    description:
      - List of ports to publish from the container to the host.
      - "Use docker CLI syntax: C(8000), C(9000:8000), or C(0.0.0.0:9000:8000), where 8000 is a
        container port, 9000 is a host port, and 0.0.0.0 is a host interface."
      - Port ranges can be used for source and destination ports. If two ranges with
        different lengths are specified, the shorter range will be used.
      - "Bind addresses must be either IPv4 or IPv6 addresses. Hostnames are I(not) allowed. This
        is different from the C(docker) command line utility. Use the L(dig lookup,../lookup/dig.html)
        to resolve hostnames."
      - Container ports must be exposed either in the Dockerfile or via the C(expose) option.
      - A value of C(all) will publish all exposed container ports to random host ports, ignoring
        any other mappings.
      - If C(networks) parameter is provided, will inspect each network to see if there exists
        a bridge network with optional parameter com.docker.network.bridge.host_binding_ipv4.
        If such a network is found, then published ports where no host IP address is specified
        will be bound to the host IP pointed to by com.docker.network.bridge.host_binding_ipv4.
        Note that the first bridge network with a com.docker.network.bridge.host_binding_ipv4
        value encountered in the list of C(networks) is the one that will be used.
    aliases:
      - ports
  pull:
    description:
       - If true, always pull the latest version of an image. Otherwise, will only pull an image
         when missing.
       - I(Note) that images are only pulled when specified by name. If the image is specified
         as a image ID (hash), it cannot be pulled.
    type: bool
    default: 'no'
  purge_networks:
    description:
       - Remove the container from ALL networks not included in C(networks) parameter.
       - Any default networks such as I(bridge), if not found in C(networks), will be removed as well.
    type: bool
    default: 'no'
  read_only:
    description:
      - Mount the container's root file system as read-only.
    type: bool
    default: 'no'
  recreate:
    description:
      - Use with present and started states to force the re-creation of an existing container.
    type: bool
    default: 'no'
  restart:
    description:
      - Use with started state to force a matching container to be stopped and restarted.
    type: bool
    default: 'no'
  restart_policy:
    description:
      - Container restart policy. Place quotes around I(no) option.
    choices:
      - 'no'
      - 'on-failure'
      - 'always'
      - 'unless-stopped'
  restart_retries:
    description:
       - Use with restart policy to control maximum number of restart attempts.
  runtime:
    description:
      - Runtime to use for the container.
  shm_size:
    description:
      - "Size of C(/dev/shm) (format: C(<number>[<unit>])). Number is positive integer.
        Unit can be C(B) (byte), C(K) (kibibyte, 1024B), C(M) (mebibyte), C(G) (gibibyte),
        C(T) (tebibyte), or C(P) (pebibyte)."
      - Omitting the unit defaults to bytes. If you omit the size entirely, the system uses C(64M).
  security_opts:
    description:
      - List of security options in the form of C("label:user:User")
  state:
    description:
      - 'I(absent) - A container matching the specified name will be stopped and removed. Use force_kill to kill the container
         rather than stopping it. Use keep_volumes to retain volumes associated with the removed container.'
      - 'I(present) - Asserts the existence of a container matching the name and any provided configuration parameters. If no
        container matches the name, a container will be created. If a container matches the name but the provided configuration
        does not match, the container will be updated, if it can be. If it cannot be updated, it will be removed and re-created
        with the requested config. Image version will be taken into account when comparing configuration. Use force_kill to kill
        the container rather than stopping it. Use keep_volumes to retain volumes associated with a removed container.'
      - 'I(started) - Asserts there is a running container matching the name and any provided configuration. If no container
        matches the name, a container will be created and started. If a container matching the name is found but the
        configuration does not match, the container will be updated, if it can be. If it cannot be updated, it will be removed
        and a new container will be created with the requested configuration and started. Image version will be taken into
        account when comparing configuration. Use recreate to always re-create a matching container, even if it is running.
        Use restart to force a matching container to be stopped and restarted. Use force_kill to kill a container rather than
        stopping it. Use keep_volumes to retain volumes associated with a removed container.'
      - 'I(stopped) - Asserts that the container is first I(present), and then if the container is running moves it to a stopped
        state. Use force_kill to kill a container rather than stopping it.'
    default: started
    choices:
      - absent
      - present
      - stopped
      - started
  stop_signal:
    description:
      - Override default signal used to stop the container.
  stop_timeout:
    description:
      - Number of seconds to wait for the container to stop before sending SIGKILL.
        When the container is created by this module, its C(StopTimeout) configuration
        will be set to this value.
      - When the container is stopped, will be used as a timeout for stopping the
        container. In case the container has a custom C(StopTimeout) configuration,
        the behavior depends on the version of docker. New versions of docker will
        always use the container's configured C(StopTimeout) value if it has been
        configured.
  trust_image_content:
    description:
      - If C(yes), skip image verification.
    type: bool
    default: 'no'
  tmpfs:
    description:
      - Mount a tmpfs directory
  tty:
    description:
      - Allocate a pseudo-TTY.
    type: bool
    default: 'no'
  ulimits:
    description:
      - "List of ulimit options. A ulimit is specified as C(nofile:262144:262144)"
  sysctls:
    description:
      - Dictionary of key,value pairs.
  user:
    description:
      - Sets the username or UID used and optionally the groupname or GID for the specified command.
      - "Can be [ user | user:group | uid | uid:gid | user:gid | uid:group ]"
  uts:
    description:
      - Set the UTS namespace mode for the container.
  volumes:
    description:
      - List of volumes to mount within the container.
      - "Use docker CLI-style syntax: C(/host:/container[:mode])"
      - "Mount modes can be a comma-separated list of various modes such as C(ro), C(rw), C(consistent),
        C(delegated), C(cached), C(rprivate), C(private), C(rshared), C(shared), C(rslave), C(slave).
        Note that docker might not support all modes and combinations of such modes."
      - SELinux hosts can additionally use C(z) or C(Z) to use a shared or
        private label for the volume.
      - "Note that Ansible 2.7 and earlier only supported one mode, which had to be one of C(ro), C(rw),
        C(z), and C(Z)."
  volume_driver:
    description:
      - The container volume driver.
  volumes_from:
    description:
      - List of container names or Ids to get volumes from.
  working_dir:
    description:
      - Path to the working directory.

author:
    - "Adam Miller (@maxamillion)"

'''

EXAMPLES = '''
- name: Create a data container
  podman_container:
    name: mydata
    image: busybox
    volumes:
      - /data

- name: Re-create a redis container
  podman_container:
    name: myredis
    image: redis
    command: redis-server --appendonly yes
    state: present
    recreate: yes
    exposed_ports:
      - 6379
    volumes_from:
      - mydata

- name: Restart a container
  podman_container:
    name: myapplication
    image: someuser/appimage
    state: started
    restart: yes
    links:
     - "myredis:aliasedredis"
    devices:
     - "/dev/sda:/dev/xvda:rwm"
    ports:
     - "8080:9000"
     - "127.0.0.1:8081:9001/udp"
    env:
        SECRET_KEY: "ssssh"
        # Values which might be parsed as numbers, booleans or other types by the YAML parser need to be quoted
        BOOLEAN_KEY: "yes"

- name: Container present
  podman_container:
    name: mycontainer
    state: present
    image: ubuntu:14.04
    command: sleep infinity

- name: Stop a container
  podman_container:
    name: mycontainer
    state: stopped

- name: Start 4 load-balanced containers
  podman_container:
    name: "container{{ item }}"
    recreate: yes
    image: someuser/anotherappimage
    command: sleep 1d
  with_sequence: count=4

- name: remove container
  podman_container:
    name: ohno
    state: absent

- name: Syslogging output
  podman_container:
    name: myservice
    image: busybox
    log_driver: syslog
    log_options:
      syslog-address: tcp://my-syslog-server:514
      syslog-facility: daemon
      # NOTE: in Docker 1.13+ the "syslog-tag" option was renamed to "tag" for
      # older docker installs, use "syslog-tag" instead
      tag: myservice

- name: Create db container and connect to network
  podman_container:
    name: db_test
    image: "postgres:latest"
    networks:
      - name: "{{ docker_network_name }}"

- name: Start container, connect to network and link
  podman_container:
    name: sleeper
    image: ubuntu:14.04
    networks:
      - name: TestingNet
        ipv4_address: "172.1.1.100"
        aliases:
          - sleepyzz
        links:
          - db_test:db
      - name: TestingNet2

- name: Start a container with a command
  podman_container:
    name: sleepy
    image: ubuntu:14.04
    command: ["sleep", "infinity"]

- name: Add container to networks
  podman_container:
    name: sleepy
    networks:
      - name: TestingNet
        ipv4_address: 172.1.1.18
        links:
          - sleeper
      - name: TestingNet2
        ipv4_address: 172.1.10.20

- name: Update network with aliases
  podman_container:
    name: sleepy
    networks:
      - name: TestingNet
        aliases:
          - sleepyz
          - zzzz

- name: Remove container from one network
  podman_container:
    name: sleepy
    networks:
      - name: TestingNet2
    purge_networks: yes

- name: Remove container from all networks
  podman_container:
    name: sleepy
    purge_networks: yes

- name: Start a container and use an env file
  podman_container:
    name: agent
    image: jenkinsci/ssh-slave
    env_file: /var/tmp/jenkins/agent.env

- name: Create a container with limited capabilities
  podman_container:
    name: sleepy
    image: ubuntu:16.04
    command: sleep infinity
    capabilities:
      - sys_time
    cap_drop:
      - all

- name: Finer container restart/update control
  podman_container:
    name: test
    image: ubuntu:18.04
    env:
      - arg1: "true"
      - arg2: "whatever"
    volumes:
      - /tmp:/tmp
    comparisons:
      image: ignore   # don't restart containers with older versions of the image
      env: strict   # we want precisely this environment
      volumes: allow_more_present   # if there are more volumes, that's ok, as long as `/tmp:/tmp` is there

- name: Finer container restart/update control II
  podman_container:
    name: test
    image: ubuntu:18.04
    env:
      - arg1: "true"
      - arg2: "whatever"
    comparisons:
      '*': ignore  # by default, ignore *all* options (including image)
      env: strict   # except for environment variables; there, we want to be strict

- name: start container with block device read limit
  podman_container:
    name: test
    image: ubuntu:18.04
    state: started
    device_read_bps:
      # Limit read rate for /dev/sda to 20 mebibytes per second
      - path: /dev/sda
        rate: 20M
    device_read_iops:
      # Limit read rate for /dev/sdb to 300 IO per second
      - path: /dev/sdb
        rate: 300
'''

RETURN = '''
podman_container:
    description:
      - Facts representing the current state of the container. Matches the podman inspect output.
      - Empty if C(state) is I(absent)
      - If detached is I(False), will include Output attribute containing any output from container run.
    returned: always
    type: dict
    sample: '{
        "ID": "04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589",
        "Created": "2019-01-29T05:27:05.525912306Z",
        "Path": "/bin/bash",
        "Args": [
            "/bin/bash"
        ],
        "State": {
            "OciVersion": "1.0.1-dev",
            "Status": "running",
            "Running": true,
            "Paused": false,
            "Restarting": false,
            "OOMKilled": false,
            "Dead": false,
            "Pid": 13812,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2019-01-29T05:27:06.783444582Z",
            "FinishedAt": "0001-01-01T00:00:00Z"
        },
        "Image": "1e1148e4cc2c148c6890a18e3b2d2dde41a6745ceb4e5fe94a923d811bf82ddb",
        "ImageName": "docker.io/library/centos:latest",
        "Rootfs": "",
        "ResolvConfPath": "/run/user/1000/vfs-containers/04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589/userdata/resolv.conf",
        "HostnamePath": "/run/user/1000/vfs-containers/04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589/userdata/hostname",
        "HostsPath": "/run/user/1000/vfs-containers/04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589/userdata/hosts",
        "StaticDir": "/home/someuser/.local/share/containers/storage/vfs-containers/04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589/userdata",
        "LogPath": "/home/someuser/.local/share/containers/storage/vfs-containers/04b15683f3ed174850a9a12397eada4d8420924b1b983d841ce4ddaae5dc1589/userdata/ctr.log",
        "Name": "clever_kalam",
        "RestartCount": 0,
        "Driver": "vfs",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "",
        "EffectiveCaps": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ],
	...
    }'
'''

from ansible.module_utils.basic import AnsibleModule

def main():

    module = AnsibleModule(
        argument_spec = dict(
            auto_remove=dict(type='bool', default=False),
            blkio_weight=dict(type='int'),
            capabilities=dict(type='list', elements='str'),
            cap_drop=dict(type='list', elements='str'),
            cleanup=dict(type='bool', default=False),
            command=dict(type='raw'),
            cpu_period=dict(type='int'),
            cpu_quota=dict(type='int'),
            cpuset_cpus=dict(type='str'),
            cpuset_mems=dict(type='str'),
            cpu_shares=dict(type='int'),
            detach=dict(type='bool', default=True),
            devices=dict(type='list', elements='str'),
            device_read_bps=dict(type='list', elements='dict', options=dict(
                path=dict(required=True, type='str'),
                rate=dict(required=True, type='str'),
            )),
            device_write_bps=dict(type='list', elements='dict', options=dict(
                path=dict(required=True, type='str'),
                rate=dict(required=True, type='str'),
            )),
            device_read_iops=dict(type='list', elements='dict', options=dict(
                path=dict(required=True, type='str'),
                rate=dict(required=True, type='int'),
            )),
            device_write_iops=dict(type='list', elements='dict', options=dict(
                path=dict(required=True, type='str'),
                rate=dict(required=True, type='int'),
            )),
            dns_servers=dict(type='list', elements='str'),
            dns_opts=dict(type='list', elements='str'),
            dns_search_domains=dict(type='list', elements='str'),
            domainname=dict(type='str'),
            entrypoint=dict(type='list', elements='str'),
            env=dict(type='dict'),
            env_file=dict(type='path'),
            etc_hosts=dict(type='dict'),
            exposed_ports=dict(type='list', aliases=['exposed', 'expose'], elements='str'),
            force_kill=dict(type='bool', default=False, aliases=['forcekill']),
            groups=dict(type='list', elements='str'),
            healthcheck=dict(type='dict', options=dict(
                test=dict(type='raw'),
                interval=dict(type='str'),
                timeout=dict(type='str'),
                start_period=dict(type='str'),
                retries=dict(type='int'),
            )),
            hostname=dict(type='str'),
            ignore_image=dict(type='bool', default=False),
            image=dict(type='str'),
            init=dict(type='bool', default=False),
            interactive=dict(type='bool', default=False),
            ipc_mode=dict(type='str'),
            keep_volumes=dict(type='bool', default=True),
            kernel_memory=dict(type='str'),
            kill_signal=dict(type='str'),
            labels=dict(type='dict'),
            links=dict(type='list', elements='str'),
            log_driver=dict(type='str'),
            log_options=dict(type='dict', aliases=['log_opt']),
            mac_address=dict(type='str'),
            memory=dict(type='str', default='0'),
            memory_reservation=dict(type='str'),
            memory_swap=dict(type='str'),
            memory_swappiness=dict(type='int'),
            name=dict(type='str', required=True),
            network_mode=dict(type='str'),
            networks=dict(type='list', elements='dict', options=dict(
                name=dict(required=True, type='str'),
                ipv4_address=dict(type='str'),
                ipv6_address=dict(type='str'),
                aliases=dict(type='list', elements='str'),
                links=dict(type='list', elements='str'),
            )),
            oom_killer=dict(type='bool'),
            oom_score_adj=dict(type='int'),
            output_logs=dict(type='bool', default=False),
            paused=dict(type='bool', default=False),
            pid_mode=dict(type='str'),
            pids_limit=dict(type='int'),
            privileged=dict(type='bool', default=False),
            published_ports=dict(type='list', aliases=['ports'], elements='str'),
            pull=dict(type='bool', default=False),
            purge_networks=dict(type='bool', default=False),
            read_only=dict(type='bool', default=False),
            recreate=dict(type='bool', default=False),
            restart=dict(type='bool', default=False),
            restart_policy=dict(type='str', choices=['no', 'on-failure', 'always', 'unless-stopped']),
            restart_retries=dict(type='int', default=None),
            runtime=dict(type='str', default=None),
            security_opts=dict(type='list', elements='str'),
            shm_size=dict(type='str'),
            state=dict(type='str', choices=['absent', 'present', 'started', 'stopped'], default='started'),
            stop_signal=dict(type='str'),
            stop_timeout=dict(type='int'),
            sysctls=dict(type='dict'),
            tmpfs=dict(type='list', elements='str'),
            trust_image_content=dict(type='bool', default=False),
            tty=dict(type='bool', default=False),
            ulimits=dict(type='list', elements='str'),
            user=dict(type='str'),
            userns_mode=dict(type='str'),
            uts=dict(type='str'),
            volume_driver=dict(type='str'),
            volumes=dict(type='list', elements='str'),
            volumes_from=dict(type='list', elements='str'),
            working_dir=dict(type='str'),
        ),
        required_if=[('state', 'present', ['image'])],
        supports_check_mode=True
    )


if __name__ == '__main__':
    main()
