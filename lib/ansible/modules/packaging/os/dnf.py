#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2015 Cristian van Ee <cristian at cvee.org>
# Copyright 2015 Igor Gnatenko <i.gnatenko.brain@gmail.com>
# Copyright 2018 Adam Miller <admiller@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}


DOCUMENTATION = '''
---
module: dnf
version_added: 1.9
short_description: Manages packages with the I(dnf) package manager
description:
     - Installs, upgrade, removes, and lists packages and groups with the I(dnf) package manager.
options:
  name:
    description:
      - "A package name or package specifier with version, like C(name-1.0).
        When using state=latest, this can be '*' which means run: dnf -y update.
        You can also pass a url or a local path to a rpm file.
        To operate on several packages this can accept a comma separated string of packages or a list of packages."
    required: true
    aliases:
        - pkg

  list:
    description:
      - Various (non-idempotent) commands for usage with C(/usr/bin/ansible) and I(not) playbooks. See examples.

  state:
    description:
      - Whether to install (C(present), C(latest)), or remove (C(absent)) a package.
      - Default is C(None), however in effect the default action is C(present) unless the C(autoremove) option is
        enabled for this module, then C(absent) is inferred.
    choices: ['absent', 'present', 'installed', 'removed', 'latest']

  enablerepo:
    description:
      - I(Repoid) of repositories to enable for the install/update operation.
        These repos will not persist beyond the transaction.
        When specifying multiple repos, separate them with a ",".

  disablerepo:
    description:
      - I(Repoid) of repositories to disable for the install/update operation.
        These repos will not persist beyond the transaction.
        When specifying multiple repos, separate them with a ",".

  conf_file:
    description:
      - The remote dnf configuration file to use for the transaction.

  disable_gpg_check:
    description:
      - Whether to disable the GPG checking of signatures of packages being
        installed. Has an effect only if state is I(present) or I(latest).
    type: bool
    default: 'no'

  installroot:
    description:
      - Specifies an alternative installroot, relative to which all packages
        will be installed.
    version_added: "2.3"
    default: "/"

  releasever:
    description:
      - Specifies an alternative release from which all packages will be
        installed.
    version_added: "2.6"

  autoremove:
    description:
      - If C(yes), removes all "leaf" packages from the system that were originally
        installed as dependencies of user-installed packages but which are no longer
        required by any such package. Should be used alone or when state is I(absent)
    type: bool
    default: "no"
    version_added: "2.4"
  exclude:
    description:
      - Package name(s) to exclude when state=present, or latest. This can be a
        list or a comma separated string.
    version_added: "2.7"
  skip_broken:
    description:
      - Skip packages with broken dependencies(devsolve) and are causing problems.
    type: bool
    default: "no"
    version_added: "2.7"
  update_cache:
    description:
      - Force yum to check if cache is out of date and redownload if needed.
        Has an effect only if state is I(present) or I(latest).
    type: bool
    default: "no"
    aliases: [ expire-cache ]
    version_added: "2.7"
  update_only:
    description:
      - When using latest, only update installed packages. Do not install packages.
      - Has an effect only if state is I(latest)
    default: "no"
    type: bool
    version_added: "2.7"
  security:
    description:
      - If set to C(yes), and C(state=latest) then only installs updates that have been marked security related.
    type: bool
    default: "no"
    version_added: "2.7"
  bugfix:
    description:
      - If set to C(yes), and C(state=latest) then only installs updates that have been marked bugfix related.
    default: "no"
    type: bool
    version_added: "2.7"
  enable_plugin:
    description:
      - I(Plugin) name to enable for the install/update operation.
        The enabled plugin will not persist beyond the transaction.
    version_added: "2.7"
  disable_plugin:
    description:
      - I(Plugin) name to disable for the install/update operation.
        The disabled plugins will not persist beyond the transaction.
    version_added: "2.7"
  disable_excludes:
    description:
      - Disable the excludes defined in DNF config files.
      - If set to C(all), disables all excludes.
      - If set to C(main), disable excludes defined in [main] in yum.conf.
      - If set to C(repoid), disable excludes defined for given repo id.
    version_added: "2.7"
  validate_certs:
    description:
      - This only applies if using a https url as the source of the rpm. e.g. for localinstall. If set to C(no), the SSL certificates will not be validated.
      - This should only set to C(no) used on personally controlled sites using self-signed certificates as it avoids verifying the source site.
    type: bool
    default: "yes"
    version_added: "2.7"
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
    version_added: "2.7"
  install_repoquery:
    description:
      - This is effectively a no-op in DNF as it is not needed with DNF, but is an accepted parameter for feature
        parity/compatibility with the I(yum) module.
    type: bool
    default: "yes"
    version_added: "2.7"
  download_only:
    description:
      - Only download the packages, do not install them.
    default: "no"
    type: bool
    version_added: "2.7"
  lock_timeout:
    description:
      - Amount of time to wait for the dnf lockfile to be freed.
    required: false
    default: 0
    type: int
    version_added: "2.8"
notes:
  - When used with a `loop:` each package will be processed individually, it is much more efficient to pass the list directly to the `name` option.
  - Group removal doesn't work if the group was installed with Ansible because
    upstream dnf's API doesn't properly mark groups as installed, therefore upon
    removal the module is unable to detect that the group is installed
    (https://bugzilla.redhat.com/show_bug.cgi?id=1620324)
requirements:
  - "python >= 2.6"
  - python-dnf
  - for the autoremove option you need dnf >= 2.0.1"
author:
  - Igor Gnatenko (@ignatenkobrain) <i.gnatenko.brain@gmail.com>
  - Cristian van Ee (@DJMuggs) <cristian at cvee.org>
  - Berend De Schouwer (@berenddeschouwer)
  - Adam Miller (@maxamillion) <admiller@redhat.com>
'''

EXAMPLES = '''
- name: install the latest version of Apache
  dnf:
    name: httpd
    state: latest

- name: install the latest version of Apache and MariaDB
  dnf:
    name:
      - httpd
      - mariadb-server
    state: latest

- name: remove the Apache package
  dnf:
    name: httpd
    state: absent

- name: install the latest version of Apache from the testing repo
  dnf:
    name: httpd
    enablerepo: testing
    state: present

- name: upgrade all packages
  dnf:
    name: "*"
    state: latest

- name: install the nginx rpm from a remote repo
  dnf:
    name: 'http://nginx.org/packages/centos/6/noarch/RPMS/nginx-release-centos-6-0.el6.ngx.noarch.rpm'
    state: present

- name: install nginx rpm from a local file
  dnf:
    name: /usr/local/src/nginx-release-centos-6-0.el6.ngx.noarch.rpm
    state: present

- name: install the 'Development tools' package group
  dnf:
    name: '@Development tools'
    state: present

- name: Autoremove unneeded packages installed as dependencies
  dnf:
    autoremove: yes

- name: Uninstall httpd but keep its dependencies
  dnf:
    name: httpd
    state: absent
    autoremove: no
'''

import os
import re
import tempfile

try:
    import dnf
    import dnf.cli
    import dnf.const
    import dnf.exceptions
    import dnf.subject
    import dnf.util
    HAS_DNF = True
except ImportError:
    HAS_DNF = False

from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six import PY2, text_type
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.yumdnf import YumDnf, yumdnf_argument_spec

from contextlib import contextmanager
from ansible.module_utils.urls import fetch_file

# 64k.  Number of bytes to read at a time when manually downloading pkgs via a url
BUFSIZE = 65536

def_qf = "%{epoch}:%{name}-%{version}-%{release}.%{arch}"
rpmbin = None


class DnfModule(YumDnf):
    """
    DNF Ansible module back-end implementation
    """

    def __init__(self, module):
        # This populates instance vars for all argument spec params
        super(DnfModule, self).__init__(module)

        self._ensure_dnf()
        self.lockfile = "/var/cache/dnf/*_lock.pid"
        self.pkg_mgr_name = "dnf"
        self.dnf_basecmd = ["dnf", "-y"]

    def _sanitize_dnf_error_msg(self, spec, error):
        """
        For unhandled dnf.exceptions.Error scenarios, there are certain error
        messages we want to filter. Do that here.
        """
        if to_text("no package matched") in to_text(error):
            return "No package {0} available.".format(spec)

        return error

    def _package_dict(self, package):
        """Return a dictionary of information for the package."""
        # NOTE: This no longer contains the 'dnfstate' field because it is
        # already known based on the query type.
        result = {
            'name': package.name,
            'arch': package.arch,
            'epoch': str(package.epoch),
            'release': package.release,
            'version': package.version,
            'repo': package.repoid}
        result['nevra'] = '{epoch}:{name}-{version}-{release}.{arch}'.format(
            **result)

        # Added for YUM3/YUM4 compat
        if package.repoid == 'installed':
            result['yumstate'] = 'installed'
        else:
            result['yumstate'] = 'available'

        return result

    def _packagename_dict(self, packagename):
        """
        Return a dictionary of information for a package name string or None
        if the package name doesn't contain at least all NVR elements
        """

        if packagename[-4:] == '.rpm':
            packagename = packagename[:-4]

        # This list was auto generated on a Fedora 28 system with the following one-liner
        #   printf '[ '; for arch in $(ls /usr/lib/rpm/platform); do  printf '"%s", ' ${arch%-linux}; done; printf ']\n'
        redhat_rpm_arches = [
            "aarch64", "alphaev56", "alphaev5", "alphaev67", "alphaev6", "alpha",
            "alphapca56", "amd64", "armv3l", "armv4b", "armv4l", "armv5tejl", "armv5tel",
            "armv5tl", "armv6hl", "armv6l", "armv7hl", "armv7hnl", "armv7l", "athlon",
            "geode", "i386", "i486", "i586", "i686", "ia32e", "ia64", "m68k", "mips64el",
            "mips64", "mips64r6el", "mips64r6", "mipsel", "mips", "mipsr6el", "mipsr6",
            "noarch", "pentium3", "pentium4", "ppc32dy4", "ppc64iseries", "ppc64le", "ppc64",
            "ppc64p7", "ppc64pseries", "ppc8260", "ppc8560", "ppciseries", "ppc", "ppcpseries",
            "riscv64", "s390", "s390x", "sh3", "sh4a", "sh4", "sh", "sparc64", "sparc64v",
            "sparc", "sparcv8", "sparcv9", "sparcv9v", "x86_64"
        ]

        rpm_arch_re = re.compile(r'(.*)\.(.*)')
        rpm_nevr_re = re.compile(r'(\S+)-(?:(\d*):)?(.*)-(~?\w+[\w.]*)')
        try:
            arch = None
            rpm_arch_match = rpm_arch_re.match(packagename)
            if rpm_arch_match:
                nevr, arch = rpm_arch_match.groups()
                if arch in redhat_rpm_arches:
                    packagename = nevr
            rpm_nevr_match = rpm_nevr_re.match(packagename)
            if rpm_nevr_match:
                name, epoch, version, release = rpm_nevr_re.match(packagename).groups()
                if not version or not version.split('.')[0].isdigit():
                    return None
            else:
                return None
        except AttributeError as e:
            self.module.fail_json(
                msg='Error attempting to parse package: %s, %s' % (packagename, to_native(e)),
                rc=1,
                results=[]
            )

        if not epoch:
            epoch = "0"

        if ':' in name:
            epoch_name = name.split(":")

            epoch = epoch_name[0]
            name = ''.join(epoch_name[1:])

        result = {
            'name': name,
            'epoch': epoch,
            'release': release,
            'version': version,
        }

        return result

    # Original implementation from yum.rpmUtils.miscutils (GPLv2+)
    #   http://yum.baseurl.org/gitweb?p=yum.git;a=blob;f=rpmUtils/miscutils.py
    def _compare_evr(self, e1, v1, r1, e2, v2, r2):
        # return 1: a is newer than b
        # 0: a and b are the same version
        # -1: b is newer than a
        if e1 is None:
            e1 = '0'
        else:
            e1 = str(e1)
        v1 = str(v1)
        r1 = str(r1)
        if e2 is None:
            e2 = '0'
        else:
            e2 = str(e2)
        v2 = str(v2)
        r2 = str(r2)
        # print '%s, %s, %s vs %s, %s, %s' % (e1, v1, r1, e2, v2, r2)
        rc = dnf.rpm.rpm.labelCompare((e1, v1, r1), (e2, v2, r2))
        # print '%s, %s, %s vs %s, %s, %s = %s' % (e1, v1, r1, e2, v2, r2, rc)
        return rc

    def fetch_rpm_from_url(self, spec):
        # FIXME: Remove this once this PR is merged:
        #   https://github.com/ansible/ansible/pull/19172

        # download package so that we can query it
        package_name, dummy = os.path.splitext(str(spec.rsplit('/', 1)[1]))
        package_file = tempfile.NamedTemporaryFile(dir=self.module.tmpdir, prefix=package_name, suffix='.rpm', delete=False)
        self.module.add_cleanup_file(package_file.name)
        try:
            rsp, info = fetch_url(self.module, spec)
            if not rsp:
                self.module.fail_json(
                    msg="Failure downloading %s, %s" % (spec, info['msg']),
                    results=[],
                )
            data = rsp.read(BUFSIZE)
            while data:
                package_file.write(data)
                data = rsp.read(BUFSIZE)
            package_file.close()
        except Exception as e:
            self.module.fail_json(
                msg="Failure downloading %s, %s" % (spec, to_native(e)),
                results=[],
            )

        return package_file.name

    def _ensure_dnf(self):
        if not HAS_DNF:
            if PY2:
                package = 'python2-dnf'
            else:
                package = 'python3-dnf'

            if self.module.check_mode:
                self.module.fail_json(
                    msg="`{0}` is not installed, but it is required"
                    "for the Ansible dnf module.".format(package),
                    results=[],
                )

            self.module.run_command(['dnf', 'install', '-y', package], check_rc=True)
            global dnf
            try:
                import dnf
                import dnf.cli
                import dnf.const
                import dnf.exceptions
                import dnf.subject
                import dnf.util
            except ImportError:
                self.module.fail_json(
                    msg="Could not import the dnf python module. "
                    "Please install `{0}` package.".format(package),
                    results=[],
                )

    def _configure_base(self, base, conf_file, disable_gpg_check, installroot='/'):
        """Configure the dnf Base object."""

        if self.enable_plugin and self.disable_plugin:
            base.init_plugins(self.disable_plugin, self.enable_plugin)
        elif self.enable_plugin:
            base.init_plugins(enable_plugins=self.enable_plugin)
        elif self.disable_plugin:
            base.init_plugins(self.disable_plugin)

        conf = base.conf

        # Turn off debug messages in the output
        conf.debuglevel = 0

        # Set whether to check gpg signatures
        conf.gpgcheck = not disable_gpg_check
        conf.localpkg_gpgcheck = not disable_gpg_check

        # Don't prompt for user confirmations
        conf.assumeyes = True

        # Set installroot
        conf.installroot = installroot

        # Handle different DNF versions immutable mutable datatypes and
        # dnf v1/v2/v3
        #
        # In DNF < 3.0 are lists, and modifying them works
        # In DNF >= 3.0 < 3.6 are lists, but modifying them doesn't work
        # In DNF >= 3.6 have been turned into tuples, to communicate that modifying them doesn't work
        #
        # https://www.happyassassin.net/2018/06/27/adams-debugging-adventures-the-immutable-mutable-object/
        #
        # Set excludes
        if self.exclude:
            _excludes = list(conf.exclude)
            _excludes.extend(self.exclude)
            conf.exclude = _excludes
        # Set disable_excludes
        if self.disable_excludes:
            _disable_excludes = list(conf.disable_excludes)
            if self.disable_excludes not in _disable_excludes:
                _disable_excludes.append(self.disable_excludes)
                conf.disable_excludes = _disable_excludes

        # Set releasever
        if self.releasever is not None:
            conf.substitutions['releasever'] = self.releasever

        # Set skip_broken (in dnf this is strict=0)
        if self.skip_broken:
            conf.strict = 0

        if self.download_only:
            conf.downloadonly = True

        # Change the configuration file path if provided
        if conf_file:
            # Fail if we can't read the configuration file.
            if not os.access(conf_file, os.R_OK):
                self.module.fail_json(
                    msg="cannot read configuration file", conf_file=conf_file,
                    results=[],
                )
            else:
                conf.config_file_path = conf_file

        # Default in dnf upstream is true
        conf.clean_requirements_on_remove = self.autoremove

        # Read the configuration file
        conf.read()

    def _specify_repositories(self, base, disablerepo, enablerepo):
        """Enable and disable repositories matching the provided patterns."""
        base.read_all_repos()
        repos = base.repos

        # Disable repositories
        for repo_pattern in disablerepo:
            if repo_pattern:
                for repo in repos.get_matching(repo_pattern):
                    repo.disable()

        # Enable repositories
        for repo_pattern in enablerepo:
            if repo_pattern:
                for repo in repos.get_matching(repo_pattern):
                    repo.enable()

    def _base(self, conf_file, disable_gpg_check, disablerepo, enablerepo, installroot):
        """Return a fully configured dnf Base object."""
        base = dnf.Base()
        self._configure_base(base, conf_file, disable_gpg_check, installroot)
        self._specify_repositories(base, disablerepo, enablerepo)
        try:
            base.fill_sack(load_system_repo='auto')
        except dnf.exceptions.RepoError as e:
            self.module.fail_json(
                msg="{0}".format(to_text(e)),
                results=[],
                rc=1
            )
        if self.bugfix:
            key = {'advisory_type__eq': 'bugfix'}
            base._update_security_filters = [base.sack.query().filter(**key)]
        if self.security:
            key = {'advisory_type__eq': 'security'}
            base._update_security_filters = [base.sack.query().filter(**key)]
        if self.update_cache:
            try:
                base.update_cache()
            except dnf.exceptions.RepoError as e:
                self.module.fail_json(
                    msg="{0}".format(to_text(e)),
                    results=[],
                    rc=1
                )
        return base

    def list_items(self, command):
        """List package info based on the command."""
        # Rename updates to upgrades
        if command == 'updates':
            command = 'upgrades'

        # Return the corresponding packages
        if command in ['installed', 'upgrades', 'available']:
            results = [
                self._package_dict(package)
                for package in getattr(self.base.sack.query(), command)()]
        # Return the enabled repository ids
        elif command in ['repos', 'repositories']:
            results = [
                {'repoid': repo.id, 'state': 'enabled'}
                for repo in self.base.repos.iter_enabled()]
        # Return any matching packages
        else:
            packages = dnf.subject.Subject(command).get_best_query(self.base.sack)
            results = [self._package_dict(package) for package in packages]

        self.module.exit_json(msg="", results=results)

    def _is_installed(self, pkg):
        installed = self.base.sack.query().installed()
        if installed.filter(name=pkg):
            return True
        else:
            return False

    def _is_newer_version_installed(self, pkg_name):
        candidate_pkg = self._packagename_dict(pkg_name)
        if not candidate_pkg:
            # The user didn't provide a versioned rpm, so version checking is
            # not required
            return False

        installed = self.base.sack.query().installed()
        installed_pkg = installed.filter(name=candidate_pkg['name']).run()
        if installed_pkg:
            installed_pkg = installed_pkg[0]

            # this looks weird but one is a dict and the other is a dnf.Package
            evr_cmp = self._compare_evr(
                installed_pkg.epoch, installed_pkg.version, installed_pkg.release,
                candidate_pkg['epoch'], candidate_pkg['version'], candidate_pkg['release'],
            )

            if evr_cmp == 1:
                return True
            else:
                return False

        else:

            return False

    def _mark_package_install(self, pkg_spec, upgrade=False):
        """Mark the package for install."""
        is_newer_version_installed = self._is_newer_version_installed(pkg_spec)
        is_installed = self._is_installed(pkg_spec)
        try:
            if self.allow_downgrade:
                # dnf only does allow_downgrade, we have to handle this ourselves
                # because it allows a possibility for non-idempotent transactions
                # on a system's package set (pending the yum repo has many old
                # NVRs indexed)
                if upgrade:
                    if is_installed:
                        self.base.upgrade(pkg_spec)
                    else:
                        self.base.install(pkg_spec)
                else:
                    self.base.install(pkg_spec)
            elif not self.allow_downgrade and is_newer_version_installed:
                return {'failed': False, 'msg': '', 'failure': '', 'rc': 0}
            elif not is_newer_version_installed:
                if upgrade:
                    if is_installed:
                        self.base.upgrade(pkg_spec)
                    else:
                        self.base.install(pkg_spec)
                else:
                    self.base.install(pkg_spec)
            else:
                if upgrade:
                    if is_installed:
                        self.base.upgrade(pkg_spec)
                    else:
                        self.base.install(pkg_spec)
                else:
                    self.base.install(pkg_spec)

            return {'failed': False, 'msg': 'Installed: {0}'.format(pkg_spec), 'failure': '', 'rc': 0}

        except dnf.exceptions.MarkingError as e:
            return {
                'failed': True,
                'msg': "No package {0} available.".format(pkg_spec),
                'failure': " ".join((pkg_spec, to_native(e))),
                'rc': 1,
                "results": []
            }

        except dnf.exceptions.DepsolveError as e:
            return {
                'failed': True,
                'msg': "Depsolve Error occured for package {0}.".format(pkg_spec),
                'failure': " ".join((pkg_spec, to_native(e))),
                'rc': 1,
                "results": []
            }

        except dnf.exceptions.Error as e:
            if to_text("already installed") in to_text(e):
                return {'failed': False, 'msg': '', 'failure': ''}
            else:
                return {
                    'failed': True,
                    'msg': "Unknown Error occured for package {0}.".format(pkg_spec),
                    'failure': " ".join((pkg_spec, to_native(e))),
                    'rc': 1,
                    "results": []
                }

    def _parse_spec_group_file(self):
        pkg_specs, grp_specs, filenames = [], [], []
        for name in self.names:
            if name.endswith(".rpm"):
                if '://' in name:
                    name = self.fetch_rpm_from_url(name)
                filenames.append(name)
            elif name.startswith("@"):
                grp_specs.append(name[1:])
            else:
                pkg_specs.append(name)
        return pkg_specs, grp_specs, filenames

    def _update_only(self, pkgs):
        not_installed = []
        for pkg in pkgs:
            if self._is_installed(pkg):
                try:
                    if isinstance(to_text(pkg), text_type):
                        self.base.upgrade(pkg)
                    else:
                        self.base.package_upgrade(pkg)
                except Exception as e:
                    self.module.fail_json(
                        msg="Error occured attempting update_only operation: {0}".format(to_native(e)),
                        results=[],
                        rc=1,
                    )
            else:
                not_installed.append(pkg)

        return not_installed

    def _install_remote_rpms(self, filenames):
        if int(dnf.__version__.split(".")[0]) >= 2:
            pkgs = list(sorted(self.base.add_remote_rpms(list(filenames)), reverse=True))
        else:
            pkgs = []
            try:
                for filename in filenames:
                    pkgs.append(self.base.add_remote_rpm(filename))
            except IOError as e:
                if to_text("Can not load RPM file") in to_text(e):
                    self.module.fail_json(
                        msg="Error occured attempting remote rpm install of package: {0}. {1}".format(filename, to_native(e)),
                        results=[],
                        rc=1,
                    )
        if self.update_only:
            self._update_only(pkgs)
        else:
            for pkg in pkgs:
                try:
                    if self._is_newer_version_installed(self._package_dict(pkg)['nevra']):
                        if self.allow_downgrade:
                            self.base.package_install(pkg)
                    else:
                            self.base.package_install(pkg)
                except Exception as e:
                    self.module.fail_json(
                        msg="Error occured attempting remote rpm operation: {0}".format(to_native(e)),
                        results=[],
                        rc=1,
                    )

    def cli_ensure(self, repoq):
        pkgs = self.names

        # autoremove was provided without `name`
        if not self.names and self.autoremove:
            pkgs = []
            self.state = 'absent'

        if self.conf_file and os.path.exists(self.conf_file):
            self.dnf_basecmd += ['-c', self.conf_file]

            if repoq:
                repoq += ['-c', self.conf_file]

        if self.skip_broken:
            self.dnf_basecmd.extend(['--skip-broken'])

        if self.disablerepo:
            self.dnf_basecmd.extend(['--disablerepo=%s' % ','.join(self.disablerepo)])

        if self.enablerepo:
            self.dnf_basecmd.extend(['--enablerepo=%s' % ','.join(self.enablerepo)])

        if self.enable_plugin:
            self.dnf_basecmd.extend(['--enableplugin', ','.join(self.enable_plugin)])

        if self.disable_plugin:
            self.dnf_basecmd.extend(['--disableplugin', ','.join(self.disable_plugin)])

        if self.exclude:
            e_cmd = ['--exclude=%s' % ','.join(self.exclude)]
            self.dnf_basecmd.extend(e_cmd)

        if self.disable_excludes:
            self.dnf_basecmd.extend(['--disableexcludes=%s' % self.disable_excludes])

        if self.download_only:
            self.dnf_basecmd.extend(['--downloadonly'])

        if self.installroot != '/':
            # do not setup installroot by default, because of error
            # CRITICAL:yum.cli:Config Error: Error accessing file for config file:////etc/yum.conf
            # in old yum version (like in CentOS 6.6)
            e_cmd = ['--installroot=%s' % self.installroot]
            self.dnf_basecmd.extend(e_cmd)

        if self.state in ('installed', 'present', 'latest'):
            """ The need of this entire if conditional has to be chalanged
                this function is the ensure function that is called
                in the main section.

                This conditional tends to disable/enable repo for
                install present latest action, same actually
                can be done for remove and absent action

                As solution I would advice to cal
                try: my.repos.disableRepo(disablerepo)
                and
                try: my.repos.enableRepo(enablerepo)
                right before any yum_cmd is actually called regardless
                of yum action.

                Please note that enable/disablerepo options are general
                options, this means that we can call those with any action
                option.  https://linux.die.net/man/8/yum

                This docstring will be removed together when issue: #21619
                will be solved.

                This has been triggered by: #19587
            """

            if self.update_cache:
                self.module.run_command(self.dnf_basecmd + ['clean', 'expire-cache'])

            my = self.yum_base()
            try:
                if self.disablerepo:
                    for rid in self.disablerepo:
                        my.repos.disableRepo(rid)
                current_repos = my.repos.repos.keys()
                if self.enablerepo:
                    try:
                        for rid in self.enablerepo:
                            my.repos.enableRepo(rid)
                        new_repos = my.repos.repos.keys()
                        for i in new_repos:
                            if i not in current_repos:
                                rid = my.repos.getRepo(i)
                                a = rid.repoXML.repoid  # nopep8 - https://github.com/ansible/ansible/pull/21475#pullrequestreview-22404868
                        current_repos = new_repos
                    except yum.Errors.YumBaseError as e:
                        self.module.fail_json(msg="Error setting/accessing repos: %s" % to_native(e))
            except yum.Errors.YumBaseError as e:
                self.module.fail_json(msg="Error accessing repos: %s" % to_native(e))
        if self.state == 'latest' or self.update_only:
            if self.disable_gpg_check:
                self.dnf_basecmd.append('--nogpgcheck')
            if self.security:
                self.dnf_basecmd.append('--security')
            if self.bugfix:
                self.dnf_basecmd.append('--bugfix')
            res = self.latest(pkgs, repoq)
        elif self.state in ('installed', 'present'):
            if self.disable_gpg_check:
                self.dnf_basecmd.append('--nogpgcheck')
            res = self.install(pkgs, repoq)
        elif self.state in ('removed', 'absent'):
            res = self.remove(pkgs, repoq)
        else:
            # should be caught by AnsibleModule argument_spec
            self.module.fail_json(
                msg="we should never get here unless this all failed",
                changed=False,
                results='',
                errors='unexpected state'
            )
        return res

    def ensure(self):
        allow_erasing = False

        response = {
            'msg': "",
            'changed': False,
            'results': [],
            'rc': 0
        }

        # Accumulate failures.  Package management modules install what they can
        # and fail with a message about what they can't.
        failure_response = {
            'msg': "",
            'failures': [],
            'results': [],
            'rc': 1
        }

        # Autoremove is called alone
        # Jump to remove path where base.autoremove() is run
        if not self.names and self.autoremove:
            self.names = []
            self.state = 'absent'

        if self.names == ['*'] and self.state == 'latest':
            try:
                self.base.upgrade_all()
            except dnf.exceptions.DepsolveError as e:
                failure_response['msg'] = "Depsolve Error occured attempting to upgrade all packages"
                self.module.fail_json(**failure_response)
        else:
            pkg_specs, group_specs, filenames = self._parse_spec_group_file()
            if group_specs:
                self.base.read_comps()

            pkg_specs = [p.strip() for p in pkg_specs]
            filenames = [f.strip() for f in filenames]
            groups = []
            environments = []
            for group_spec in (g.strip() for g in group_specs):
                group = self.base.comps.group_by_pattern(group_spec)
                if group:
                    groups.append(group.id)
                else:
                    environment = self.base.comps.environment_by_pattern(group_spec)
                    if environment:
                        environments.append(environment.id)
                    else:
                        self.module.fail_json(
                            msg="No group {0} available.".format(group_spec),
                            results=[],
                        )

            if self.state in ['installed', 'present']:
                # Install files.
                self._install_remote_rpms(filenames)
                for filename in filenames:
                    response['results'].append("Installed {0}".format(filename))

                # Install groups.
                for group in groups:
                    try:
                        group_pkg_count_installed = self.base.group_install(group, dnf.const.GROUP_PACKAGE_TYPES)
                        if group_pkg_count_installed == 0:
                            response['results'].append("Group {0} already installed.".format(group))
                        else:
                            response['results'].append("Group {0} installed.".format(group))
                    except dnf.exceptions.DepsolveError as e:
                        failure_response['msg'] = "Depsolve Error occured attempting to install group: {0}".format(group)
                        self.module.fail_json(**failure_response)
                    except dnf.exceptions.Error as e:
                        # In dnf 2.0 if all the mandatory packages in a group do
                        # not install, an error is raised.  We want to capture
                        # this but still install as much as possible.
                        failure_response['failures'].append(" ".join((group, to_native(e))))

                for environment in environments:
                    try:
                        self.base.environment_install(environment, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.DepsolveError as e:
                        failure_response['msg'] = "Depsolve Error occured attempting to install environment: {0}".format(environment)
                        self.module.fail_json(**failure_response)
                    except dnf.exceptions.Error as e:
                        failure_response['failures'].append(" ".join((environment, to_native(e))))

                # Install packages.
                if self.update_only:
                    not_installed = self._update_only(pkg_specs)
                    for spec in not_installed:
                        response['results'].append("Packages providing %s not installed due to update_only specified" % spec)
                else:
                    for pkg_spec in pkg_specs:
                        install_result = self._mark_package_install(pkg_spec)
                        if install_result['failed']:
                            failure_response['msg'] += install_result['msg']
                            failure_response['failures'].append(self._sanitize_dnf_error_msg(pkg_spec, install_result['failure']))
                        else:
                            response['results'].append(install_result['msg'])

            elif self.state == 'latest':
                # "latest" is same as "installed" for filenames.
                self._install_remote_rpms(filenames)
                for filename in filenames:
                    response['results'].append("Installed {0}".format(filename))

                for group in groups:
                    try:
                        try:
                            self.base.group_upgrade(group)
                            response['results'].append("Group {0} upgraded.".format(group))
                        except dnf.exceptions.CompsError:
                            if not self.update_only:
                                # If not already installed, try to install.
                                group_pkg_count_installed = self.base.group_install(group, dnf.const.GROUP_PACKAGE_TYPES)
                                if group_pkg_count_installed == 0:
                                    response['results'].append("Group {0} already installed.".format(group))
                                else:
                                    response['results'].append("Group {0} installed.".format(group))
                    except dnf.exceptions.Error as e:
                        failure_response['failures'].append(" ".join((group, to_native(e))))

                for environment in environments:
                    try:
                        try:
                            self.base.environment_upgrade(environment)
                        except dnf.exceptions.CompsError:
                            # If not already installed, try to install.
                            self.base.environment_install(environment, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.DepsolveError as e:
                        failure_response['msg'] = "Depsolve Error occured attempting to install environment: {0}".format(environment)
                    except dnf.exceptions.Error as e:
                        failure_response['failures'].append(" ".join((environment, to_native(e))))

                if self.update_only:
                    not_installed = self._update_only(pkg_specs)
                    for spec in not_installed:
                        response['results'].append("Packages providing %s not installed due to update_only specified" % spec)
                else:
                    for pkg_spec in pkg_specs:
                        # best effort causes to install the latest package
                        # even if not previously installed
                        self.base.conf.best = True
                        install_result = self._mark_package_install(pkg_spec, upgrade=True)
                        if install_result['failed']:
                            failure_response['msg'] += install_result['msg']
                            failure_response['failures'].append(self._sanitize_dnf_error_msg(pkg_spec, install_result['failure']))
                        else:
                            response['results'].append(install_result['msg'])

            else:
                # state == absent
                if filenames:
                    self.module.fail_json(
                        msg="Cannot remove paths -- please specify package name.",
                        results=[],
                    )

                for group in groups:
                    try:
                        self.base.group_remove(group)
                    except dnf.exceptions.CompsError:
                        # Group is already uninstalled.
                        pass
                    except AttributeError:
                        # Group either isn't installed or wasn't marked installed at install time
                        # because of DNF bug
                        #
                        # This is necessary until the upstream dnf API bug is fixed where installing
                        # a group via the dnf API doesn't actually mark the group as installed
                        #   https://bugzilla.redhat.com/show_bug.cgi?id=1620324
                        pass

                for environment in environments:
                    try:
                        self.base.environment_remove(environment)
                    except dnf.exceptions.CompsError:
                        # Environment is already uninstalled.
                        pass

                installed = self.base.sack.query().installed()
                for pkg_spec in pkg_specs:
                    if ("*" in pkg_spec) or installed.filter(name=pkg_spec):
                        self.base.remove(pkg_spec)

                # Like the dnf CLI we want to allow recursive removal of dependent
                # packages
                allow_erasing = True

                if self.autoremove:
                    self.base.autoremove()

        try:
            if not self.base.resolve(allow_erasing=allow_erasing):
                if failure_response['failures']:
                    failure_response['msg'] = 'Failed to install some of the specified packages'
                    self.module.fail_json(**failure_response)

                response['msg'] = "Nothing to do"
                self.module.exit_json(**response)
            else:
                response['changed'] = True
                if self.module.check_mode:
                    if failure_response['failures']:
                        failure_response['msg'] = 'Failed to install some of the specified packages',
                        self.module.fail_json(**failure_response)
                    response['msg'] = "Check mode: No changes made, but would have if not in check mode"
                    self.module.exit_json(**response)

                try:
                    self.base.download_packages(self.base.transaction.install_set)
                except dnf.exceptions.DownloadError as e:
                    self.module.fail_json(
                        msg="Failed to download packages: {0}".format(to_text(e)),
                        results=[],
                    )

                if self.download_only:
                    for package in self.base.transaction.install_set:
                        response['results'].append("Downloaded: {0}".format(package))
                    self.module.exit_json(**response)
                else:
                    self.base.do_transaction()
                    for package in self.base.transaction.install_set:
                        response['results'].append("Installed: {0}".format(package))
                    for package in self.base.transaction.remove_set:
                        response['results'].append("Removed: {0}".format(package))

                if failure_response['failures']:
                    failure_response['msg'] = 'Failed to install some of the specified packages',
                    self.module.exit_json(**response)
                self.module.exit_json(**response)
        except dnf.exceptions.DepsolveError as e:
            failure_response['msg'] = "Depsolve Error occured: {0}".format(to_native(e))
            self.module.fail_json(**failure_response)
        except dnf.exceptions.Error as e:
            if to_text("already installed") in to_text(e):
                response['changed'] = False
                response['results'].append("Package already installed: {0}".format(to_native(e)))
                self.module.exit_json(**response)
            else:
                failure_response['msg'] = "Unknown Error occured: {0}".format(to_native(e))
                self.module.fail_json(**failure_response)

    @staticmethod
    def has_dnf():
        return HAS_DNF

    def run(self):
        """The main function."""

        # Check if autoremove is called correctly
        if self.autoremove:
            if LooseVersion(dnf.__version__) < LooseVersion('2.0.1'):
                self.module.fail_json(
                    msg="Autoremove requires dnf>=2.0.1. Current dnf version is %s" % dnf.__version__,
                    results=[],
                )

        if self.update_cache and not self.names and not self.list:
            rc, out, err = self.module.run_command(self.dnf_basecmd + ['makecache'])
            if rc == 0:
                self.module.exit_json(
                    msg="Cache updated",
                    changed=False,
                    results=[out],
                    rc=rc
                )
            else:
                self.module.fail_json(
                    msg="Failed to update cache",
                    changed=False,
                    results=[err],
                    rc=rc
                )

        # Set state as installed by default
        # This is not set in AnsibleModule() because the following shouldn't happend
        # - dnf: autoremove=yes state=installed
        if self.state is None:
            self.state = 'installed'

        if self.list:
            self.base = self._base(
                self.conf_file, self.disable_gpg_check, self.disablerepo,
                self.enablerepo, self.installroot
            )
            self.list_items(self.list)
        else:
            # Note: base takes a long time to run so we want to check for failure
            # before running it.
            if not dnf.util.am_i_root():
                self.module.fail_json(
                    msg="This command has to be run under the root user.",
                    results=[],
                )
            self.base = self._base(
                self.conf_file, self.disable_gpg_check, self.disablerepo,
                self.enablerepo, self.installroot
            )

            self.ensure()










############# YUM YUM YUM YUM
    def po_to_envra(self, po):
        if hasattr(po, 'ui_envra'):
            return po.ui_envra

        return '%s:%s-%s-%s.%s' % (po.epoch, po.name, po.version, po.release, po.arch)

    def is_available(self, repoq, pkgspec, qf=def_qf):
        if not repoq:

            pkgs = []
            try:
                my = self.yum_base()
                for rid in self.disablerepo:
                    my.repos.disableRepo(rid)
                for rid in self.enablerepo:
                    my.repos.enableRepo(rid)

                e, m, _ = my.pkgSack.matchPackageNames([pkgspec])
                pkgs = e + m
                if not pkgs:
                    pkgs.extend(my.returnPackagesByDep(pkgspec))
            except Exception as e:
                self.module.fail_json(msg="Failure talking to yum: %s" % to_native(e))

            return [self.po_to_envra(p) for p in pkgs]

        else:
            myrepoq = list(repoq)

            r_cmd = ['--disablerepo', ','.join(self.disablerepo)]
            myrepoq.extend(r_cmd)

            r_cmd = ['--enablerepo', ','.join(self.enablerepo)]
            myrepoq.extend(r_cmd)

            cmd = myrepoq + ["--qf", qf, pkgspec]
            rc, out, err = self.module.run_command(cmd)
            if rc == 0:
                return [p for p in out.split('\n') if p.strip()]
            else:
                self.module.fail_json(msg='Error from repoquery: %s: %s' % (cmd, err))

        return []

    def is_update(self, repoq, pkgspec, qf=def_qf):
        if not repoq:

            pkgs = []
            updates = []

            try:
                my = self.yum_base()
                for rid in self.disablerepo:
                    my.repos.disableRepo(rid)
                for rid in self.enablerepo:
                    my.repos.enableRepo(rid)

                pkgs = my.returnPackagesByDep(pkgspec) + my.returnInstalledPackagesByDep(pkgspec)
                if not pkgs:
                    e, m, _ = my.pkgSack.matchPackageNames([pkgspec])
                    pkgs = e + m
                updates = my.doPackageLists(pkgnarrow='updates').updates
            except Exception as e:
                self.module.fail_json(msg="Failure talking to yum: %s" % to_native(e))

            retpkgs = (pkg for pkg in pkgs if pkg in updates)

            return set(self.po_to_envra(p) for p in retpkgs)

        else:
            myrepoq = list(repoq)
            r_cmd = ['--disablerepo', ','.join(self.disablerepo)]
            myrepoq.extend(r_cmd)

            r_cmd = ['--enablerepo', ','.join(self.enablerepo)]
            myrepoq.extend(r_cmd)

            cmd = myrepoq + ["--pkgnarrow=updates", "--qf", qf, pkgspec]
            rc, out, err = self.module.run_command(cmd)

            if rc == 0:
                return set(p for p in out.split('\n') if p.strip())
            else:
                self.module.fail_json(msg='Error from repoquery: %s: %s' % (cmd, err))

        return set()

    def what_provides(self, repoq, req_spec, qf=def_qf):
        if not repoq:

            pkgs = []
            try:
                my = self.yum_base()
                for rid in self.disablerepo:
                    my.repos.disableRepo(rid)
                for rid in self.enablerepo:
                    my.repos.enableRepo(rid)

                try:
                    pkgs = my.returnPackagesByDep(req_spec) + my.returnInstalledPackagesByDep(req_spec)
                except Exception as e:
                    # If a repo with `repo_gpgcheck=1` is added and the repo GPG
                    # key was never accepted, quering this repo will throw an
                    # error: 'repomd.xml signature could not be verified'. In that
                    # situation we need to run `yum -y makecache` which will accept
                    # the key and try again.
                    if 'repomd.xml signature could not be verified' in to_native(e):
                        self.module.run_command(self.dnf_basecmd + ['makecache'])
                        pkgs = my.returnPackagesByDep(req_spec) + my.returnInstalledPackagesByDep(req_spec)
                    else:
                        raise
                if not pkgs:
                    e, m, _ = my.pkgSack.matchPackageNames([req_spec])
                    pkgs.extend(e)
                    pkgs.extend(m)
                    e, m, _ = my.rpmdb.matchPackageNames([req_spec])
                    pkgs.extend(e)
                    pkgs.extend(m)
            except Exception as e:
                self.module.fail_json(msg="Failure talking to yum: %s" % to_native(e))

            return set(self.po_to_envra(p) for p in pkgs)

        else:
            myrepoq = list(repoq)
            r_cmd = ['--disablerepo', ','.join(self.disablerepo)]
            myrepoq.extend(r_cmd)

            r_cmd = ['--enablerepo', ','.join(self.enablerepo)]
            myrepoq.extend(r_cmd)

            cmd = myrepoq + ["--qf", qf, "--whatprovides", req_spec]
            rc, out, err = self.module.run_command(cmd)
            cmd = myrepoq + ["--qf", qf, req_spec]
            rc2, out2, err2 = self.module.run_command(cmd)
            if rc == 0 and rc2 == 0:
                out += out2
                pkgs = set([p for p in out.split('\n') if p.strip()])
                if not pkgs:
                    pkgs = self.is_installed(repoq, req_spec, qf=qf)
                return pkgs
            else:
                self.module.fail_json(msg='Error from repoquery: %s: %s' % (cmd, err + err2))

        return set()

    def transaction_exists(self, pkglist):
        """
        checks the package list to see if any packages are
        involved in an incomplete transaction
        """

        conflicts = []
        if not transaction_helpers:
            return conflicts

        # first, we create a list of the package 'nvreas'
        # so we can compare the pieces later more easily
        pkglist_nvreas = (splitFilename(pkg) for pkg in pkglist)

        # next, we build the list of packages that are
        # contained within an unfinished transaction
        unfinished_transactions = find_unfinished_transactions()
        for trans in unfinished_transactions:
            steps = find_ts_remaining(trans)
            for step in steps:
                # the action is install/erase/etc., but we only
                # care about the package spec contained in the step
                (action, step_spec) = step
                (n, v, r, e, a) = splitFilename(step_spec)
                # and see if that spec is in the list of packages
                # requested for installation/updating
                for pkg in pkglist_nvreas:
                    # if the name and arch match, we're going to assume
                    # this package is part of a pending transaction
                    # the label is just for display purposes
                    label = "%s-%s" % (n, a)
                    if n == pkg[0] and a == pkg[4]:
                        if label not in conflicts:
                            conflicts.append("%s-%s" % (n, a))
                        break
        return conflicts

    def local_envra(self, path):
        """return envra of a local rpm passed in"""

        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        fd = os.open(path, os.O_RDONLY)
        try:
            header = ts.hdrFromFdno(fd)
        except rpm.error as e:
            return None
        finally:
            os.close(fd)

        return '%s:%s-%s-%s.%s' % (
            header[rpm.RPMTAG_EPOCH] or '0',
            header[rpm.RPMTAG_NAME],
            header[rpm.RPMTAG_VERSION],
            header[rpm.RPMTAG_RELEASE],
            header[rpm.RPMTAG_ARCH]
        )

    @contextmanager
    def set_env_proxy(self):
        # setting system proxy environment and saving old, if exists
        my = self.yum_base()
        namepass = ""
        proxy_url = ""
        scheme = ["http", "https"]
        old_proxy_env = [os.getenv("http_proxy"), os.getenv("https_proxy")]
        try:
            if my.conf.proxy:
                if my.conf.proxy_username:
                    namepass = namepass + my.conf.proxy_username
                    proxy_url = my.conf.proxy
                    if my.conf.proxy_password:
                        namepass = namepass + ":" + my.conf.proxy_password
                elif '@' in my.conf.proxy:
                    namepass = my.conf.proxy.split('@')[0].split('//')[-1]
                    proxy_url = my.conf.proxy.replace("{0}@".format(namepass), "")

                if namepass:
                    namepass = namepass + '@'
                    for item in scheme:
                        os.environ[item + "_proxy"] = re.sub(
                            r"(http://)",
                            r"\g<1>" + namepass, proxy_url
                        )
            yield
        except yum.Errors.YumBaseError:
            raise
        finally:
            # revert back to previously system configuration
            for item in scheme:
                if os.getenv("{0}_proxy".format(item)):
                    del os.environ["{0}_proxy".format(item)]
            if old_proxy_env[0]:
                os.environ["http_proxy"] = old_proxy_env[0]
            if old_proxy_env[1]:
                os.environ["https_proxy"] = old_proxy_env[1]

    def pkg_to_dict(self, pkgstr):
        if pkgstr.strip():
            n, e, v, r, a, repo = pkgstr.split('|')
        else:
            return {'error_parsing': pkgstr}

        d = {
            'name': n,
            'arch': a,
            'epoch': e,
            'release': r,
            'version': v,
            'repo': repo,
            'envra': '%s:%s-%s-%s.%s' % (e, n, v, r, a)
        }

        if repo == 'installed':
            d['yumstate'] = 'installed'
        else:
            d['yumstate'] = 'available'

        return d

    def exec_install(self, items, action, pkgs, res):
        cmd = self.dnf_basecmd + [action] + pkgs

        if self.module.check_mode:
            self.module.exit_json(changed=True, results=res['results'], changes=dict(installed=pkgs))

        lang_env = dict(LANG='C', LC_ALL='C', LC_MESSAGES='C')
        rc, out, err = self.module.run_command(cmd, environ_update=lang_env)

        if rc == 1:
            for spec in items:
                # Fail on invalid urls:
                if ('://' in spec and ('No package %s available.' % spec in out or 'Cannot open: %s. Skipping.' % spec in err)):
                    err = 'Package at %s could not be installed' % spec
                    self.module.fail_json(changed=False, msg=err, rc=rc)

        res['rc'] = rc
        res['results'].append(out)
        res['msg'] += err
        res['changed'] = True

        if ('Nothing to do' in out and rc == 0) or ('does not have any packages' in err):
            res['changed'] = False

        if rc != 0:
            res['changed'] = False
            self.module.fail_json(**res)

        # Fail if yum prints 'No space left on device' because that means some
        # packages failed executing their post install scripts because of lack of
        # free space (e.g. kernel package couldn't generate initramfs). Note that
        # yum can still exit with rc=0 even if some post scripts didn't execute
        # correctly.
        if 'No space left on device' in (out or err):
            res['changed'] = False
            res['msg'] = 'No space left on device'
            self.module.fail_json(**res)

        # FIXME - if we did an install - go and check the rpmdb to see if it actually installed
        # look for each pkg in rpmdb
        # look for each pkg via obsoletes

        return res

    def install(self, items, repoq):

        pkgs = []
        downgrade_pkgs = []
        res = {}
        res['results'] = []
        res['msg'] = ''
        res['rc'] = 0
        res['changed'] = False

        for spec in items:
            pkg = None
            downgrade_candidate = False

            # check if pkgspec is installed (if possible for idempotence)
            if spec.endswith('.rpm'):
                if '://' not in spec and not os.path.exists(spec):
                    res['msg'] += "No RPM file matching '%s' found on system" % spec
                    res['results'].append("No RPM file matching '%s' found on system" % spec)
                    res['rc'] = 127  # Ensure the task fails in with-loop
                    self.module.fail_json(**res)

                if '://' in spec:
                    with self.set_env_proxy():
                        package = fetch_file(self.module, spec)
                else:
                    package = spec

                # most common case is the pkg is already installed
                envra = self.local_envra(package)
                if envra is None:
                    self.module.fail_json(msg="Failed to get nevra information from RPM package: %s" % spec)
                installed_pkgs = self.is_installed(repoq, envra)
                if installed_pkgs:
                    res['results'].append('%s providing %s is already installed' % (installed_pkgs[0], package))
                    continue

                (name, ver, rel, epoch, arch) = splitFilename(envra)
                installed_pkgs = self.is_installed(repoq, name)

                # case for two same envr but differrent archs like x86_64 and i686
                if len(installed_pkgs) == 2:
                    (cur_name0, cur_ver0, cur_rel0, cur_epoch0, cur_arch0) = splitFilename(installed_pkgs[0])
                    (cur_name1, cur_ver1, cur_rel1, cur_epoch1, cur_arch1) = splitFilename(installed_pkgs[1])
                    cur_epoch0 = cur_epoch0 or '0'
                    cur_epoch1 = cur_epoch1 or '0'
                    compare = compareEVR((cur_epoch0, cur_ver0, cur_rel0), (cur_epoch1, cur_ver1, cur_rel1))
                    if compare == 0 and cur_arch0 != cur_arch1:
                        for installed_pkg in installed_pkgs:
                            if installed_pkg.endswith(arch):
                                installed_pkgs = [installed_pkg]

                if len(installed_pkgs) == 1:
                    installed_pkg = installed_pkgs[0]
                    (cur_name, cur_ver, cur_rel, cur_epoch, cur_arch) = splitFilename(installed_pkg)
                    cur_epoch = cur_epoch or '0'
                    compare = compareEVR((cur_epoch, cur_ver, cur_rel), (epoch, ver, rel))

                    # compare > 0 -> higher version is installed
                    # compare == 0 -> exact version is installed
                    # compare < 0 -> lower version is installed
                    if compare > 0 and self.allow_downgrade:
                        downgrade_candidate = True
                    elif compare >= 0:
                        continue

                # else: if there are more installed packages with the same name, that would mean
                # kernel, gpg-pubkey or like, so just let yum deal with it and try to install it

                pkg = package

            # groups
            elif spec.startswith('@'):
                if self.is_group_env_installed(spec):
                    continue

                pkg = spec

            # range requires or file-requires or pkgname :(
            else:
                # most common case is the pkg is already installed and done
                # short circuit all the bs - and search for it as a pkg in is_installed
                # if you find it then we're done
                if not set(['*', '?']).intersection(set(spec)):
                    installed_pkgs = self.is_installed(repoq, spec, is_pkg=True)
                    if installed_pkgs:
                        res['results'].append('%s providing %s is already installed' % (installed_pkgs[0], spec))
                        continue

                # look up what pkgs provide this
                pkglist = self.what_provides(repoq, spec)
                if not pkglist:
                    res['msg'] += "No package matching '%s' found available, installed or updated" % spec
                    res['results'].append("No package matching '%s' found available, installed or updated" % spec)
                    res['rc'] = 126  # Ensure the task fails in with-loop
                    self.module.fail_json(**res)

                # if any of the packages are involved in a transaction, fail now
                # so that we don't hang on the yum operation later
                conflicts = self.transaction_exists(pkglist)
                if conflicts:
                    res['msg'] += "The following packages have pending transactions: %s" % ", ".join(conflicts)
                    res['rc'] = 125  # Ensure the task fails in with-loop
                    self.module.fail_json(**res)

                # if any of them are installed
                # then nothing to do

                found = False
                for this in pkglist:
                    if self.is_installed(repoq, this, is_pkg=True):
                        found = True
                        res['results'].append('%s providing %s is already installed' % (this, spec))
                        break

                # if the version of the pkg you have installed is not in ANY repo, but there are
                # other versions in the repos (both higher and lower) then the previous checks won't work.
                # so we check one more time. This really only works for pkgname - not for file provides or virt provides
                # but virt provides should be all caught in what_provides on its own.
                # highly irritating
                if not found:
                    if self.is_installed(repoq, spec):
                        found = True
                        res['results'].append('package providing %s is already installed' % (spec))

                if found:
                    continue

                # Downgrade - The yum install command will only install or upgrade to a spec version, it will
                # not install an older version of an RPM even if specified by the install spec. So we need to
                # determine if this is a downgrade, and then use the yum downgrade command to install the RPM.
                if self.allow_downgrade:
                    for package in pkglist:
                        # Get the NEVRA of the requested package using pkglist instead of spec because pkglist
                        #  contains consistently-formatted package names returned by yum, rather than user input
                        #  that is often not parsed correctly by splitFilename().
                        (name, ver, rel, epoch, arch) = splitFilename(package)

                        # Check if any version of the requested package is installed
                        inst_pkgs = self.is_installed(repoq, name, is_pkg=True)
                        if inst_pkgs:
                            (cur_name, cur_ver, cur_rel, cur_epoch, cur_arch) = splitFilename(inst_pkgs[0])
                            compare = compareEVR((cur_epoch, cur_ver, cur_rel), (epoch, ver, rel))
                            if compare > 0:
                                downgrade_candidate = True
                            else:
                                downgrade_candidate = False
                                break

                # If package needs to be installed/upgraded/downgraded, then pass in the spec
                # we could get here if nothing provides it but that's not
                # the error we're catching here
                pkg = spec

            if downgrade_candidate and self.allow_downgrade:
                downgrade_pkgs.append(pkg)
            else:
                pkgs.append(pkg)

        if downgrade_pkgs:
            res = self.exec_install(items, 'downgrade', downgrade_pkgs, res)

        if pkgs:
            res = self.exec_install(items, 'install', pkgs, res)

        return res

    def remove(self, items, repoq):

        pkgs = []
        res = {}
        res['results'] = []
        res['msg'] = ''
        res['changed'] = False
        res['rc'] = 0

        for pkg in items:
            if pkg.startswith('@'):
                installed = self.is_group_env_installed(pkg)
            else:
                installed = self.is_installed(repoq, pkg)

            if installed:
                pkgs.append(pkg)
            else:
                res['results'].append('%s is not installed' % pkg)

        if pkgs:
            if self.module.check_mode:
                self.module.exit_json(changed=True, results=res['results'], changes=dict(removed=pkgs))

            # run an actual yum transaction
            if self.autoremove:
                cmd = self.dnf_basecmd + ["autoremove"] + pkgs
            else:
                cmd = self.dnf_basecmd + ["remove"] + pkgs

            rc, out, err = self.module.run_command(cmd)

            res['rc'] = rc
            res['results'].append(out)
            res['msg'] = err

            if rc != 0:
                if self.autoremove:
                    if 'No such command' not in out:
                        self.module.fail_json(msg='Version of YUM too old for autoremove: Requires yum 3.4.3 (RHEL/CentOS 7+)')
                else:
                    self.module.fail_json(**res)

            # compile the results into one batch. If anything is changed
            # then mark changed
            # at the end - if we've end up failed then fail out of the rest
            # of the process

            # at this point we check to see if the pkg is no longer present
            for pkg in pkgs:
                if pkg.startswith('@'):
                    installed = self.is_group_env_installed(pkg)
                else:
                    installed = self.is_installed(repoq, pkg)

                if installed:
                    # Return a mesage so it's obvious to the user why yum failed
                    # and which package couldn't be removed. More details:
                    # https://github.com/ansible/ansible/issues/35672
                    res['msg'] = "Package '%s' couldn't be removed!" % pkg
                    self.module.fail_json(**res)

            res['changed'] = True

        return res

    def run_check_update(self):
        # run check-update to see if we have packages pending
        rc, out, err = self.module.run_command(self.dnf_basecmd + ['check-update'])
        return rc, out, err

    @staticmethod
    def parse_check_update(check_update_output):
        updates = {}
        obsoletes = {}

        # remove incorrect new lines in longer columns in output from yum check-update
        # yum line wrapping can move the repo to the next line
        #
        # Meant to filter out sets of lines like:
        #  some_looooooooooooooooooooooooooooooooooooong_package_name   1:1.2.3-1.el7
        #                                                                    some-repo-label
        #
        # But it also needs to avoid catching lines like:
        # Loading mirror speeds from cached hostfile
        #
        # ceph.x86_64                               1:11.2.0-0.el7                    ceph

        # preprocess string and filter out empty lines so the regex below works
        out = re.sub(r'\n[^\w]\W+(.*)', r' \1', check_update_output)

        available_updates = out.split('\n')

        # build update dictionary
        for line in available_updates:
            line = line.split()
            # ignore irrelevant lines
            # '*' in line matches lines like mirror lists:
            #      * base: mirror.corbina.net
            # len(line) != 3 or 6 could be junk or a continuation
            # len(line) = 6 is package obsoletes
            #
            # FIXME: what is  the '.' not in line  conditional for?

            if '*' in line or len(line) not in [3, 6] or '.' not in line[0]:
                continue
            else:
                pkg, version, repo = line[0], line[1], line[2]
                name, dist = pkg.rsplit('.', 1)
                updates.update({name: {'version': version, 'dist': dist, 'repo': repo}})

                if len(line) == 6:
                    obsolete_pkg, obsolete_version, obsolete_repo = line[3], line[4], line[5]
                    obsolete_name, obsolete_dist = obsolete_pkg.rsplit('.', 1)
                    obsoletes.update({obsolete_name: {'version': obsolete_version, 'dist': obsolete_dist, 'repo': obsolete_repo}})

        return updates, obsoletes

    def latest(self, items, repoq):

        res = {}
        res['results'] = []
        res['msg'] = ''
        res['changed'] = False
        res['rc'] = 0
        pkgs = {}
        pkgs['update'] = []
        pkgs['install'] = []
        updates = {}
        obsoletes = {}
        update_all = False
        cmd = None

        # determine if we're doing an update all
        if '*' in items:
            update_all = True

        rc, out, err = self.run_check_update()

        if rc == 0 and update_all:
            res['results'].append('Nothing to do here, all packages are up to date')
            return res
        elif rc == 100:
            updates, obsoletes = self.parse_check_update(out)
        elif rc == 1:
            res['msg'] = err
            res['rc'] = rc
            self.module.fail_json(**res)

        if update_all:
            cmd = self.dnf_basecmd + ['update']
            will_update = set(updates.keys())
            will_update_from_other_package = dict()
        else:
            will_update = set()
            will_update_from_other_package = dict()
            for spec in items:
                # some guess work involved with groups. update @<group> will install the group if missing
                if spec.startswith('@'):
                    pkgs['update'].append(spec)
                    will_update.add(spec)
                    continue

                # check if pkgspec is installed (if possible for idempotence)
                # localpkg
                elif spec.endswith('.rpm') and '://' not in spec:
                    if not os.path.exists(spec):
                        res['msg'] += "No RPM file matching '%s' found on system" % spec
                        res['results'].append("No RPM file matching '%s' found on system" % spec)
                        res['rc'] = 127  # Ensure the task fails in with-loop
                        self.module.fail_json(**res)

                    # get the pkg e:name-v-r.arch
                    envra = self.local_envra(spec)

                    if envra is None:
                        self.module.fail_json(msg="Failed to get nevra information from RPM package: %s" % spec)

                    # local rpm files can't be updated
                    if self.is_installed(repoq, envra):
                        pkgs['update'].append(spec)
                    else:
                        pkgs['install'].append(spec)
                    continue

                # URL
                elif '://' in spec:
                    # download package so that we can check if it's already installed
                    with self.set_env_proxy():
                        package = fetch_file(self.module, spec)
                    envra = self.local_envra(package)

                    if envra is None:
                        self.module.fail_json(msg="Failed to get nevra information from RPM package: %s" % spec)

                    # local rpm files can't be updated
                    if self.is_installed(repoq, envra):
                        pkgs['update'].append(spec)
                    else:
                        pkgs['install'].append(spec)
                    continue

                # dep/pkgname  - find it
                else:
                    if self.is_installed(repoq, spec):
                        pkgs['update'].append(spec)
                    else:
                        pkgs['install'].append(spec)
                pkglist = self.what_provides(repoq, spec)
                # FIXME..? may not be desirable to throw an exception here if a single package is missing
                if not pkglist:
                    res['msg'] += "No package matching '%s' found available, installed or updated" % spec
                    res['results'].append("No package matching '%s' found available, installed or updated" % spec)
                    res['rc'] = 126  # Ensure the task fails in with-loop
                    self.module.fail_json(**res)

                nothing_to_do = True
                for pkg in pkglist:
                    if spec in pkgs['install'] and self.is_available(repoq, pkg):
                        nothing_to_do = False
                        break

                    # this contains the full NVR and spec could contain wildcards
                    # or virtual provides (like "python-*" or "smtp-daemon") while
                    # updates contains name only.
                    pkgname, _, _, _, _ = splitFilename(pkg)
                    if spec in pkgs['update'] and pkgname in updates:
                        nothing_to_do = False
                        will_update.add(spec)
                        # Massage the updates list
                        if spec != pkgname:
                            # For reporting what packages would be updated more
                            # succinctly
                            will_update_from_other_package[spec] = pkgname
                        break

                if not self.is_installed(repoq, spec) and self.update_only:
                    res['results'].append("Packages providing %s not installed due to update_only specified" % spec)
                    continue
                if nothing_to_do:
                    res['results'].append("All packages providing %s are up to date" % spec)
                    continue

                # if any of the packages are involved in a transaction, fail now
                # so that we don't hang on the yum operation later
                conflicts = self.transaction_exists(pkglist)
                if conflicts:
                    res['msg'] += "The following packages have pending transactions: %s" % ", ".join(conflicts)
                    res['results'].append("The following packages have pending transactions: %s" % ", ".join(conflicts))
                    res['rc'] = 128  # Ensure the task fails in with-loop
                    self.module.fail_json(**res)

        # check_mode output
        if self.module.check_mode:
            to_update = []
            for w in will_update:
                if w.startswith('@'):
                    to_update.append((w, None))
                elif w not in updates:
                    other_pkg = will_update_from_other_package[w]
                    to_update.append(
                        (
                            w,
                            'because of (at least) %s-%s.%s from %s' % (
                                other_pkg,
                                updates[other_pkg]['version'],
                                updates[other_pkg]['dist'],
                                updates[other_pkg]['repo']
                            )
                        )
                    )
                else:
                    to_update.append((w, '%s.%s from %s' % (updates[w]['version'], updates[w]['dist'], updates[w]['repo'])))

            if self.update_only:
                res['changes'] = dict(installed=[], updated=to_update)
            else:
                res['changes'] = dict(installed=pkgs['install'], updated=to_update)

            if will_update or pkgs['install']:
                res['changed'] = True

            if obsoletes:
                res['obsoletes'] = obsoletes

            return res

        # run commands
        if cmd:     # update all
            rc, out, err = self.module.run_command(cmd)
            res['changed'] = True
        elif self.update_only:
            if pkgs['update']:
                cmd = self.dnf_basecmd + ['update'] + pkgs['update']
                lang_env = dict(LANG='C', LC_ALL='C', LC_MESSAGES='C')
                rc, out, err = self.module.run_command(cmd, environ_update=lang_env)
                out_lower = out.strip().lower()
                if not out_lower.endswith("no packages marked for update") and \
                        not out_lower.endswith("nothing to do"):
                    res['changed'] = True
            else:
                rc, out, err = [0, '', '']
        elif pkgs['install'] or will_update and not self.update_only:
            cmd = self.dnf_basecmd + ['install'] + pkgs['install'] + pkgs['update']
            lang_env = dict(LANG='C', LC_ALL='C', LC_MESSAGES='C')
            rc, out, err = self.module.run_command(cmd, environ_update=lang_env)
            out_lower = out.strip().lower()
            if not out_lower.endswith("no packages marked for update") and \
                    not out_lower.endswith("nothing to do"):
                res['changed'] = True
        else:
            rc, out, err = [0, '', '']

        res['rc'] = rc
        res['msg'] += err
        res['results'].append(out)

        if rc:
            res['failed'] = True

        if obsoletes:
            res['obsoletes'] = obsoletes

        return res

    def ensure(self, repoq):
        pkgs = self.names

        # autoremove was provided without `name`
        if not self.names and self.autoremove:
            pkgs = []
            self.state = 'absent'

        if self.conf_file and os.path.exists(self.conf_file):
            self.dnf_basecmd += ['-c', self.conf_file]

            if repoq:
                repoq += ['-c', self.conf_file]

        if self.skip_broken:
            self.dnf_basecmd.extend(['--skip-broken'])

        if self.disablerepo:
            self.dnf_basecmd.extend(['--disablerepo=%s' % ','.join(self.disablerepo)])

        if self.enablerepo:
            self.dnf_basecmd.extend(['--enablerepo=%s' % ','.join(self.enablerepo)])

        if self.enable_plugin:
            self.dnf_basecmd.extend(['--enableplugin', ','.join(self.enable_plugin)])

        if self.disable_plugin:
            self.dnf_basecmd.extend(['--disableplugin', ','.join(self.disable_plugin)])

        if self.exclude:
            e_cmd = ['--exclude=%s' % ','.join(self.exclude)]
            self.dnf_basecmd.extend(e_cmd)

        if self.disable_excludes:
            self.dnf_basecmd.extend(['--disableexcludes=%s' % self.disable_excludes])

        if self.download_only:
            self.dnf_basecmd.extend(['--downloadonly'])

        if self.installroot != '/':
            # do not setup installroot by default, because of error
            # CRITICAL:yum.cli:Config Error: Error accessing file for config file:////etc/yum.conf
            # in old yum version (like in CentOS 6.6)
            e_cmd = ['--installroot=%s' % self.installroot]
            self.dnf_basecmd.extend(e_cmd)

        if self.state in ('installed', 'present', 'latest'):
            """ The need of this entire if conditional has to be chalanged
                this function is the ensure function that is called
                in the main section.

                This conditional tends to disable/enable repo for
                install present latest action, same actually
                can be done for remove and absent action

                As solution I would advice to cal
                try: my.repos.disableRepo(disablerepo)
                and
                try: my.repos.enableRepo(enablerepo)
                right before any yum_cmd is actually called regardless
                of yum action.

                Please note that enable/disablerepo options are general
                options, this means that we can call those with any action
                option.  https://linux.die.net/man/8/yum

                This docstring will be removed together when issue: #21619
                will be solved.

                This has been triggered by: #19587
            """

            if self.update_cache:
                self.module.run_command(self.dnf_basecmd + ['clean', 'expire-cache'])

            my = self.yum_base()
            try:
                if self.disablerepo:
                    for rid in self.disablerepo:
                        my.repos.disableRepo(rid)
                current_repos = my.repos.repos.keys()
                if self.enablerepo:
                    try:
                        for rid in self.enablerepo:
                            my.repos.enableRepo(rid)
                        new_repos = my.repos.repos.keys()
                        for i in new_repos:
                            if i not in current_repos:
                                rid = my.repos.getRepo(i)
                                a = rid.repoXML.repoid  # nopep8 - https://github.com/ansible/ansible/pull/21475#pullrequestreview-22404868
                        current_repos = new_repos
                    except yum.Errors.YumBaseError as e:
                        self.module.fail_json(msg="Error setting/accessing repos: %s" % to_native(e))
            except yum.Errors.YumBaseError as e:
                self.module.fail_json(msg="Error accessing repos: %s" % to_native(e))
        if self.state == 'latest' or self.update_only:
            if self.disable_gpg_check:
                self.dnf_basecmd.append('--nogpgcheck')
            if self.security:
                self.dnf_basecmd.append('--security')
            if self.bugfix:
                self.dnf_basecmd.append('--bugfix')
            res = self.latest(pkgs, repoq)
        elif self.state in ('installed', 'present'):
            if self.disable_gpg_check:
                self.dnf_basecmd.append('--nogpgcheck')
            res = self.install(pkgs, repoq)
        elif self.state in ('removed', 'absent'):
            res = self.remove(pkgs, repoq)
        else:
            # should be caught by AnsibleModule argument_spec
            self.module.fail_json(
                msg="we should never get here unless this all failed",
                changed=False,
                results='',
                errors='unexpected state'
            )
        return res

    @staticmethod
    def has_yum():
        return HAS_YUM_PYTHON

    def run(self):
        """
        actually execute the module code backend
        """

        error_msgs = []
        if not HAS_RPM_PYTHON:
            error_msgs.append('The Python 2 bindings for rpm are needed for this module. If you require Python 3 support use the `dnf` Ansible module instead.')
        if not HAS_YUM_PYTHON:
            error_msgs.append('The Python 2 yum module is needed for this module. If you require Python 3 support use the `dnf` Ansible module instead.')

        self.wait_for_lock()

        if self.disable_excludes and yum.__version_info__ < (3, 4):
            self.module.fail_json(msg="'disable_includes' is available in yum version 3.4 and onwards.")

        if error_msgs:
            self.module.fail_json(msg='. '.join(error_msgs))

        if self.update_cache and not self.names and not self.list:
            rc, stdout, stderr = self.module.run_command(self.dnf_basecmd + ['clean', 'expire-cache'])
            if rc == 0:
                self.module.exit_json(
                    changed=False,
                    msg="Cache updated",
                    rc=rc,
                    results=[]
                )
            else:
                self.module.exit_json(
                    changed=False,
                    msg="Failed to update cache",
                    rc=rc,
                    results=[stderr],
                )

        # fedora will redirect yum to dnf, which has incompatibilities
        # with how this module expects yum to operate. If yum-deprecated
        # is available, use that instead to emulate the old behaviors.
        if self.module.get_bin_path('yum-deprecated'):
            yumbin = self.module.get_bin_path('yum-deprecated')
        else:
            yumbin = self.module.get_bin_path('yum')

        repoquerybin = self.module.get_bin_path('repoquery', required=False)

        if self.install_repoquery and not repoquerybin and not self.module.check_mode:
            yum_path = self.module.get_bin_path('yum')
            if yum_path:
                self.module.run_command('%s -y install yum-utils' % yum_path)
            repoquerybin = self.module.get_bin_path('repoquery', required=False)

        if self.list:
            if not repoquerybin:
                self.module.fail_json(msg="repoquery is required to use list= with this module. Please install the yum-utils package.")
            results = {'results': self.list_stuff(repoquerybin, self.list)}
        else:
            # If rhn-plugin is installed and no rhn-certificate is available on
            # the system then users will see an error message using the yum API.
            # Use repoquery in those cases.

            my = self.yum_base()
            # A sideeffect of accessing conf is that the configuration is
            # loaded and plugins are discovered
            my.conf
            repoquery = None
            try:
                yum_plugins = my.plugins._plugins
            except AttributeError:
                pass
            else:
                if 'rhnplugin' in yum_plugins:
                    if repoquerybin:
                        repoquery = [repoquerybin, '--show-duplicates', '--plugins', '--quiet']
                        if self.installroot != '/':
                            repoquery.extend(['--installroot', self.installroot])

            results = self.ensure(repoquery)
            if repoquery:
                results['msg'] = '%s %s' % (
                    results.get('msg', ''),
                    'Warning: Due to potential bad behaviour with rhnplugin and certificates, used slower repoquery calls instead of Yum API.'
                )

        self.module.exit_json(**results)










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
        **yumdnf_argument_spec
    )

    module_implementation = DnfModule(module)
    try:
        module_implementation.run()
    except dnf.exceptions.RepoError as de:
        module.fail_json(
            msg="Failed to synchronize repodata: {0}".format(to_native(de)),
            rc=1,
            results=[],
            changed=False
        )


if __name__ == '__main__':
    main()
