#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2015 Cristian van Ee <cristian at cvee.org>
# Copyright 2015 Igor Gnatenko <i.gnatenko.brain@gmail.com>
# Copyright 2018 Adam Miller <admiller@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os

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

from ansible.module_utils._text import to_native
from ansible.module_utils.six import PY2
from distutils.version import LooseVersion


class DnfModuleUtil(object):
    """
    DNF Ansible module back-end implementation
    """

    def __init__(self, module):
        self.module = module
        self.params = module.params

        self._ensure_dnf()

    def _ensure_dnf(self):
        if not HAS_DNF:
            if PY2:
                package = 'python2-dnf'
            else:
                package = 'python3-dnf'

            if self.module.check_mode:
                self.module.fail_json(msg="`{0}` is not installed, but it is required"
                                "for the Ansible dnf module.".format(package))

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
                self.module.fail_json(msg="Could not import the dnf python module. "
                                    "Please install `{0}` package.".format(package))


    def _configure_base(self, base, conf_file, disable_gpg_check, installroot='/'):
        """Configure the dnf Base object."""
        conf = base.conf

        # Turn off debug messages in the output
        conf.debuglevel = 0

        # Set whether to check gpg signatures
        conf.gpgcheck = not disable_gpg_check

        # Don't prompt for user confirmations
        conf.assumeyes = True

        # Set installroot
        conf.installroot = installroot

        # Set releasever
        if self.params['releasever'] is not None:
            conf.substitutions['releasever'] = self.params['releasever']

        # Change the configuration file path if provided
        if conf_file:
            # Fail if we can't read the configuration file.
            if not os.access(conf_file, os.R_OK):
                self.module.fail_json(
                    msg="cannot read configuration file", conf_file=conf_file)
            else:
                conf.config_file_path = conf_file

        # Read the configuration file
        conf.read()


    def _specify_repositories(self, base, disablerepo, enablerepo):
        """Enable and disable repositories matching the provided patterns."""
        base.read_all_repos()
        repos = base.repos

        # Disable repositories
        for repo_pattern in disablerepo:
            for repo in repos.get_matching(repo_pattern):
                repo.disable()

        # Enable repositories
        for repo_pattern in enablerepo:
            for repo in repos.get_matching(repo_pattern):
                repo.enable()


    def _base(self, conf_file, disable_gpg_check, disablerepo, enablerepo, installroot):
        """Return a fully configured dnf Base object."""
        base = dnf.Base()
        self._configure_base(base, conf_file, disable_gpg_check, installroot)
        self._specify_repositories(base, disablerepo, enablerepo)
        base.fill_sack(load_system_repo='auto')
        return base


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

        return result

    def run(self):
        """The main function."""

        # Check if autoremove is called correctly
        if self.params['autoremove']:
            if LooseVersion(dnf.__version__) < LooseVersion('2.0.1'):
                self.module.fail_json(msg="Autoremove requires dnf>=2.0.1. Current dnf version is %s" % dnf.__version__)
            if self.params['state'] not in ["absent", None]:
                self.module.fail_json(msg="Autoremove should be used alone or with state=absent")

        # Set state as installed by default
        # This is not set in AnsibleModule() because the following shouldn't happend
        # - dnf: autoremove=yes state=installed
        if self.params['state'] is None:
            self.params['state'] = 'installed'

        if self.params['list']:
            self.base = self._base(
                self.params['conf_file'], self.params['disable_gpg_check'],
                self.params['disablerepo'], self.params['enablerepo'], self.params['installroot']
            )
            self.list_items(self.module, self.params['list'])
        else:
            # Note: base takes a long time to run so we want to check for failure
            # before running it.
            if not dnf.util.am_i_root():
                self.module.fail_json(msg="This command has to be run under the root user.")
            self.base = self._base(
                self.params['conf_file'], self.params['disable_gpg_check'],
                self.params['disablerepo'], self.params['enablerepo'], self.params['installroot']
            )

            self.ensure(self.params['state'], self.params['name'], self.params['autoremove'])

    def list_items(self, command):
        """List package info based on the command."""
        # Rename updates to upgrades
        if command == 'updates':
            command = 'upgrades'

        # Return the corresponding packages
        if command in ['installed', 'upgrades', 'available']:
            results = [
                _package_dict(package)
                for package in getattr(self.base.sack.query(), command)()]
        # Return the enabled repository ids
        elif command in ['repos', 'repositories']:
            results = [
                {'repoid': repo.id, 'state': 'enabled'}
                for repo in self.base.repos.iter_enabled()]
        # Return any matching packages
        else:
            packages = dnf.subject.Subject(command).get_best_query(self.base.sack)
            results = [_package_dict(package) for package in packages]

        self.module.exit_json(results=results)


    def _mark_package_install(self, pkg_spec):
        """Mark the package for install."""
        try:
            self.base.install(pkg_spec)
        except dnf.exceptions.MarkingError:
            self.module.fail_json(msg="No package {0} available.".format(pkg_spec))


    def _parse_spec_group_file(self, names):
        pkg_specs, grp_specs, filenames = [], [], []
        for name in names:
            if name.endswith(".rpm"):
                filenames.append(name)
            elif name.startswith("@"):
                grp_specs.append(name[1:])
            else:
                pkg_specs.append(name)
        return pkg_specs, grp_specs, filenames


    def _install_remote_rpms(self, filenames):
        if int(dnf.__version__.split(".")[0]) >= 2:
            pkgs = list(sorted(self.base.add_remote_rpms(list(filenames)), reverse=True))
        else:
            pkgs = []
            for filename in filenames:
                pkgs.append(self.base.add_remote_rpm(filename))
        for pkg in pkgs:
            self.base.package_install(pkg)


    def ensure(self, state, names, autoremove):
        # Accumulate failures.  Package management modules install what they can
        # and fail with a message about what they can't.
        failures = []
        allow_erasing = False

        # Autoremove is called alone
        # Jump to remove path where base.autoremove() is run
        if not names and autoremove:
            names = []
            state = 'absent'

        if names == ['*'] and state == 'latest':
            self.base.upgrade_all()
        else:
            pkg_specs, group_specs, filenames = self._parse_spec_group_file(names)
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
                            msg="No group {0} available.".format(group_spec))

            if state in ['installed', 'present']:
                # Install files.
                self._install_remote_rpms(filenames)

                # Install groups.
                for group in groups:
                    try:
                        self.base.group_install(group, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.Error as e:
                        # In dnf 2.0 if all the mandatory packages in a group do
                        # not install, an error is raised.  We want to capture
                        # this but still install as much as possible.
                        failures.append((group, to_native(e)))

                for environment in environments:
                    try:
                        self.base.environment_install(environment, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.Error as e:
                        failures.append((environment, to_native(e)))

                # Install packages.
                for pkg_spec in pkg_specs:
                    self._mark_package_install(pkg_spec)

            elif state == 'latest':
                # "latest" is same as "installed" for filenames.
                self._install_remote_rpms(filenames)

                for group in groups:
                    try:
                        try:
                            self.base.group_upgrade(group)
                        except dnf.exceptions.CompsError:
                            # If not already installed, try to install.
                            self.base.group_install(group, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.Error as e:
                        failures.append((group, to_native(e)))

                for environment in environments:
                    try:
                        try:
                            self.base.environment_upgrade(environment)
                        except dnf.exceptions.CompsError:
                            # If not already installed, try to install.
                            self.base.environment_install(environment, dnf.const.GROUP_PACKAGE_TYPES)
                    except dnf.exceptions.Error as e:
                        failures.append((environment, to_native(e)))

                for pkg_spec in pkg_specs:
                    # best effort causes to install the latest package
                    # even if not previously installed
                    self.base.conf.best = True
                    try:
                        self.base.install(pkg_spec)
                    except dnf.exceptions.MarkingError as e:
                        failures.append((pkg_spec, to_native(e)))

            else:
                # state == absent
                if autoremove:
                    self.base.conf.clean_requirements_on_remove = autoremove

                if filenames:
                    self.module.fail_json(
                        msg="Cannot remove paths -- please specify package name.")

                for group in groups:
                    try:
                        self.base.group_remove(group)
                    except dnf.exceptions.CompsError:
                        # Group is already uninstalled.
                        pass

                for environment in environments:
                    try:
                        self.base.environment_remove(environment)
                    except dnf.exceptions.CompsError:
                        # Environment is already uninstalled.
                        pass

                installed = self.base.sack.query().installed()
                for pkg_spec in pkg_specs:
                    if installed.filter(name=pkg_spec):
                        self.base.remove(pkg_spec)

                # Like the dnf CLI we want to allow recursive removal of dependent
                # packages
                allow_erasing = True

                if autoremove:
                    self.base.autoremove()

        if not self.base.resolve(allow_erasing=allow_erasing):
            if failures:
                self.module.fail_json(msg='Failed to install some of the '
                                    'specified packages',
                                failures=failures)
            self.module.exit_json(msg="Nothing to do")
        else:
            if self.module.check_mode:
                if failures:
                    self.module.fail_json(msg='Failed to install some of the '
                                        'specified packages',
                                    failures=failures)
                self.module.exit_json(changed=True)

            self.base.download_packages(self.base.transaction.install_set)
            self.base.do_transaction()
            response = {'changed': True, 'results': []}
            for package in self.base.transaction.install_set:
                response['results'].append("Installed: {0}".format(package))
            for package in self.base.transaction.remove_set:
                response['results'].append("Removed: {0}".format(package))

            if failures:
                self.module.fail_json(msg='Failed to install some of the '
                                    'specified packages',
                                failures=failures)
            self.module.exit_json(**response)

    @staticmethod
    def has_dnf():
        return HAS_DNF


if __name__ == '__main__':
    main()
