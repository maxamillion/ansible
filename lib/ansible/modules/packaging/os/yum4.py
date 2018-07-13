#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2012, Red Hat, Inc
# Written by Seth Vidal <skvidal at fedoraproject.org>
# Copyright: (c) 2014, Epic Games, Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}

DOCUMENTATION = '''
---
module: yum4
version_added: 2.8
short_description: Manages packages with the I(yum) and I(dnf) package managers,
                   this is a merger of the old I(yum) and I(dnf) Ansible Modules
                   in order to properly support yum 3.x, yum 4.x (dnf backend),
                   and dnf natively.
description:
     - Installs, upgrade, downgrades, removes, and lists packages and groups with the I(yum) package manager.
     - This module only works on Python 2. If you require Python 3 support see the M(dnf) module.
options:
  name:
    description:
      - A package name or package specifier with version, like C(name-1.0).
      - If a previous version is specified, the task also needs to turn C(allow_downgrade) on.
        See the C(allow_downgrade) documentation for caveats with downgrading packages.
      - When using state=latest, this can be C('*') which means run C(yum -y update).
      - You can also pass a url or a local path to a rpm file (using state=present).
        To operate on several packages this can accept a comma separated list of packages or (as of 2.0) a list of packages.
    aliases: [ pkg ]
  exclude:
    description:
      - Package name(s) to exclude when state=present, or latest
    version_added: "2.0"
  list:
    description:
      - "Package name to run the equivalent of yum list <package> against. In addition to listing packages,
        use can also list the following: C(installed), C(updates), C(available) and C(repos)."
  state:
    description:
      - Whether to install (C(present) or C(installed), C(latest)), or remove (C(absent) or C(removed)) a package.
      - C(present) and C(installed) will simply ensure that a desired package is installed.
      - C(latest) will update the specified package if it's not of the latest available version.
      - C(absent) and C(removed) will remove the specified package.
    choices: [ absent, installed, latest, present, removed ]
    default: present
  enablerepo:
    description:
      - I(Repoid) of repositories to enable for the install/update operation.
        These repos will not persist beyond the transaction.
        When specifying multiple repos, separate them with a C(",").
    version_added: "0.9"
  disablerepo:
    description:
      - I(Repoid) of repositories to disable for the install/update operation.
        These repos will not persist beyond the transaction.
        When specifying multiple repos, separate them with a C(",").
    version_added: "0.9"
  conf_file:
    description:
      - The remote yum configuration file to use for the transaction.
    version_added: "0.6"
  disable_gpg_check:
    description:
      - Whether to disable the GPG checking of signatures of packages being
        installed. Has an effect only if state is I(present) or I(latest).
    type: bool
    default: "no"
    version_added: "1.2"
  skip_broken:
    description:
      - Skip packages with broken dependencies(devsolve) and are causing problems.
    type: bool
    default: "no"
    version_added: "2.3"
  update_cache:
    description:
      - Force yum to check if cache is out of date and redownload if needed.
        Has an effect only if state is I(present) or I(latest).
    type: bool
    default: "no"
    aliases: [ expire-cache ]
    version_added: "1.9"
  validate_certs:
    description:
      - This only applies if using a https url as the source of the rpm. e.g. for localinstall. If set to C(no), the SSL certificates will not be validated.
      - This should only set to C(no) used on personally controlled sites using self-signed certificates as it avoids verifying the source site.
      - Prior to 2.1 the code worked as if this was set to C(yes).
    type: bool
    default: "yes"
    version_added: "2.1"

  update_only:
    description:
      - When using latest, only update installed packages. Do not install packages.
      - Has an effect only if state is I(latest)
    required: false
    default: "no"
    type: bool
    version_added: "2.5"

  installroot:
    description:
      - Specifies an alternative installroot, relative to which all packages
        will be installed.
    default: "/"
    version_added: "2.3"
  security:
    description:
      - If set to C(yes), and C(state=latest) then only installs updates that have been marked security related.
    type: bool
    default: "no"
    version_added: "2.4"
  bugfix:
    description:
      - If set to C(yes), and C(state=latest) then only installs updates that have been marked bugfix related.
    required: false
    default: "no"
    version_added: "2.6"
  allow_downgrade:
    description:
      - Specify if the named package and version is allowed to downgrade
        a maybe already installed higher version of that package.
        Note that setting allow_downgrade=True can make this module
        behave in a non-idempotent way. The task could end up with a set
        of packages that does not match the complete list of specified
        packages to install (because dependencies between the downgraded
        package and others can cause changes to the packages which were
        in the earlier transaction).
    type: bool
    default: "no"
    version_added: "2.4"
  enable_plugin:
    description:
      - I(Plugin) name to enable for the install/update operation.
        The enabled plugin will not persist beyond the transaction.
    required: false
    version_added: "2.5"
  disable_plugin:
    description:
      - I(Plugin) name to disable for the install/update operation.
        The disabled plugins will not persist beyond the transaction.
    required: false
    version_added: "2.5"
notes:
  - When used with a `loop:` each package will be processed individually,
    it is much more efficient to pass the list directly to the `name` option.
  - In versions prior to 1.9.2 this module installed and removed each package
    given to the yum module separately. This caused problems when packages
    specified by filename or url had to be installed or removed together. In
    1.9.2 this was fixed so that packages are installed in one yum
    transaction. However, if one of the packages adds a new yum repository
    that the other packages come from (such as epel-release) then that package
    needs to be installed in a separate task. This mimics yum's command line
    behaviour.
  - 'Yum itself has two types of groups.  "Package groups" are specified in the
    rpm itself while "environment groups" are specified in a separate file
    (usually by the distribution).  Unfortunately, this division becomes
    apparent to ansible users because ansible needs to operate on the group
    of packages in a single transaction and yum requires groups to be specified
    in different ways when used in that way.  Package groups are specified as
    "@development-tools" and environment groups are "@^gnome-desktop-environment".
    Use the "yum group list" command to see which category of group the group
    you want to install falls into.'
# informational: requirements for nodes
requirements:
- yum
author:
    - Ansible Core Team
    - Seth Vidal
    - Eduard Snesarev (@verm666)
    - Berend De Schouwer (@berenddeschouwer)
    - Abhijeet Kasurde (@Akasurde)
'''

EXAMPLES = '''
- name: install the latest version of Apache
  yum:
    name: httpd
    state: latest

- name: ensure a list of packages installed
  yum:
    name: "{{ packages }}"
  vars:
    packages:
    - httpd
    - httpd-tools

- name: remove the Apache package
  yum:
    name: httpd
    state: absent

- name: install the latest version of Apache from the testing repo
  yum:
    name: httpd
    enablerepo: testing
    state: present

- name: install one specific version of Apache
  yum:
    name: httpd-2.2.29-1.4.amzn1
    state: present

- name: upgrade all packages
  yum:
    name: '*'
    state: latest

- name: upgrade all packages, excluding kernel & foo related packages
  yum:
    name: '*'
    state: latest
    exclude: kernel*,foo*

- name: install the nginx rpm from a remote repo
  yum:
    name: http://nginx.org/packages/centos/6/noarch/RPMS/nginx-release-centos-6-0.el6.ngx.noarch.rpm
    state: present

- name: install nginx rpm from a local file
  yum:
    name: /usr/local/src/nginx-release-centos-6-0.el6.ngx.noarch.rpm
    state: present

- name: install the 'Development tools' package group
  yum:
    name: "@Development tools"
    state: present

- name: install the 'Gnome desktop' environment group
  yum:
    name: "@^gnome-desktop-environment"
    state: present

- name: List ansible packages and register result to print with debug later.
  yum:
    list: ansible
  register: result

- name: Install package with multiple repos enabled
  yum:
    name: sos
    enablerepo: "epel,ol7_latest"

- name: Install package with multiple repos disabled
  yum:
    name: sos
    disablerepo: "epel,ol7_latest"

- name: Install a list of packages
  yum:
    name:
      - nginx
      - postgresql
      - postgresql-server
    state: present
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.yum import YumModuleUtil
from ansible.module_utils.dnf import DnfModuleUtil

def main():
    # state=installed name=pkgspec
    # state=removed name=pkgspec
    # state=latest name=pkgspec
    #
    # informational commands:
    #   list=installed
    #   list=updates
    #   list=available
    #   list=repos
    #   list=pkgspec

    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='list', aliases=['pkg']),
            exclude=dict(type='str'),
            # removed==absent, installed==present, these are accepted as aliases
            state=dict(type='str', default='installed', choices=['absent', 'installed', 'latest', 'present', 'removed']),
            enablerepo=dict(type='list', default=[]),
            disablerepo=dict(type='list', default=[]),
            list=dict(type='str'),
            conf_file=dict(type='str'),
            disable_gpg_check=dict(type='bool', default=False),
            skip_broken=dict(type='bool', default=False),
            update_cache=dict(type='bool', default=False, aliases=['expire-cache']),
            validate_certs=dict(type='bool', default=True),
            installroot=dict(type='str', default="/"),
            update_only=dict(required=False, default="no", type='bool'),
            # this should not be needed, but exists as a failsafe
            install_repoquery=dict(type='bool', default=True),
            allow_downgrade=dict(type='bool', default=False),
            security=dict(type='bool', default=False),
            bugfix=dict(required=False, type='bool', default=False),
            enable_plugin=dict(type='list', default=[]),
            disable_plugin=dict(type='list', default=[]),
            autoremove=dict(type='bool', default=False),
            releasever=dict(default=None),
        ),
        required_one_of=[['name', 'list']],
        mutually_exclusive=[['name', 'list']],
        supports_check_mode=True,
    )

    if YumModuleUtil.has_yum():
        module_implementation = YumModuleUtil(module)
    elif DnfModuleUtil.has_dnf():
        module_implementation = DnfModuleUtil(module)
    else:
        module.fail_json(msg="No package provider found")

    module_implementation.run()


if __name__ == '__main__':
    main()
