########################################################################
#
# (C) 2015, Brian Coca <bcoca@ansible.com>
# (C) 2018, Adam Miller <admiller@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import errno
import datetime
import os
import tarfile
import tempfile
import yaml
import subprocess
import shutil
from distutils.version import LooseVersion
from shutil import rmtree

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
from ansible.module_utils.six import string_types
from ansible.playbook.role.requirement import RoleRequirement
from ansible.galaxy.api import GalaxyAPI
from ansible.galaxy import Galaxy

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

VALID_ROLE_SPEC_KEYS = [
    'name',
    'role',
    'scm',
    'src',
    'version',
]

# FIXME - need some stuff here
VALID_CONTENT_SPEC_KEYS = [

]


class GalaxyContent(object):

    SUPPORTED_SCMS = set(['git', 'hg'])
    META_MAIN = os.path.join('meta', 'main.yml')
    GALAXY_FILE = os.path.join('ansible-galaxy.yml')
    META_INSTALL = os.path.join('meta', '.galaxy_install_info')
    ROLE_DIRS = ('defaults', 'files', 'handlers', 'meta', 'tasks', 'templates', 'vars', 'tests')

    def __init__(self, galaxy, name, src=None, version=None, scm=None, path=None, type="role"):
        """
        The GalaxyContent type is meant to supercede the old GalaxyRole type,
        supporting all Galaxy Content Types as per the Galaxy Repository Metadata
        specification.

        The "type" is default to "role" in order to maintain backward
        compatibility as a drop-in replacement for GalaxyRole

        :param galaxy: Galaxy object from ansible.galaxy
        :param name: str, name of Galaxy Content desired
        :kw src: str, source uri
        :kw version: str, version required/requested
        :kw scm: str, scm type
        :kw path: str, local path to Galaxy Content
        :kw type: str, Galaxy Content type
        """

        self._metadata = None
        self._galaxy_metadata = None
        self._install_info = None
        self._validate_certs = not galaxy.options.ignore_certs

        display.debug('Validate TLS certificates: %s' % self._validate_certs)

        self.options = galaxy.options
        self.galaxy = galaxy

        self.name = name
        self.version = version
        self.src = src or name
        self.scm = scm

        # This is a marker needed to make certain decisions about single
        # content type vs all content found in the repository archive when
        # extracting files
        self._install_all_content = False
        if type == "all":
            self._install_all_content = True

        self._set_type(type)

        if self.type not in C.CONTENT_TYPES and self.type != "all":
            raise AnsibleError("%s is not a valid Galaxy Content Type" % self.type)

        # Set original path, needed to determine what action to take in order to
        # maintain backwards compat with legacy roles
        self._orig_path = path

        # Set self.path and self.path_dir
        self._set_content_paths(path)

    def __repr__(self):
        """
        Returns "content_name (version) type" if version is not null
        Returns "content_name type" otherwise
        """
        if self.version:
            return "%s (%s) %s" % (self.name, self.version, self.type)
        else:
            return "%s %s" % (self.name, self.type)

    def __eq__(self, other):
        return self.name == other.name

    def _set_type(self, new_type):
        """
        Set the internal type information, because GalaxyContent can contain
        many different types this needs to be able to change state depending on
        content installation.

        This will update:
            self.type
            self.type_dir

        :param new_type: str, new type to assign
        """

        # FIXME - Anytime we change state like this, it feels wrong. Should
        #         probably evaluate a better way to do this.
        self.type = new_type

        # We need this because the type_dir inside a Galaxy Content archive is
        # not the same as it's installed location as per the CONTENT_TYPE_DIR_MAP
        # for some types
        self.type_dir = "%ss" % new_type

    def _set_content_paths(self, path=None):
        """
        Conditionally set content path based on content type
        """
        content_paths = "" #FIXME - handle multiple content types here

        # FIXME - ":" is a placeholder default value for --content_path in the
        #         galaxy cli and it should really not be
        if path != None and path != ":":
            # "all" doesn't actually exist, but it's an internal idea that means
            # "we're going to install everything", however that comes with the
            # caveot of needing to inspect to find out if there's a meta/main.yml
            # and handling a legacy role type accordingly
            if self.name not in path and self.type in ["role", "all"]:
                path = os.path.join(path, self.name)
            self.path = path

            # We need for first set self.path (as we did above) in order to then
            # allow the property function "metadata" to check for the existence
            # of a meta/main.yml and it not, then we don't join the name to the
            # end of the path because it's not necessary for non-role content
            # types as they aren't namespaced by directory
            if not self.metadata:
                self.path = path
            else:
                # If we find a meta/main.yml, this is a legacy role and we need
                # to handle it
                self._set_type("role")
                self._install_all_content = False

            self.paths = [path]
        else:
            # First, populate the self.galaxy.content_paths for processing below

            # Unfortunately this exception is needed and we can't easily rely
            # on the dir_map because there's not consistency of plural vs
            # singular of type between the contants vars read in from the config
            # file and the subdirectories
            if self.type != "all":
                self.galaxy.content_paths = [os.path.join(p, C.CONTENT_TYPE_DIR_MAP[self.type]) for p in C.DEFAULT_CONTENT_PATH]
            else:
                self.galaxy.content_paths = C.DEFAULT_CONTENT_PATH

            # use the first path by default
            if self.type == "role":
                self.path = os.path.join(self.galaxy.content_paths[0], self.name)
            else:
                self.path = self.galaxy.content_paths[0]
            # create list of possible paths
            self.paths = [x for x in self.galaxy.content_paths]
            self.paths = [os.path.join(x, self.name) for x in self.paths]

    @property
    def metadata(self):
        """
        Returns role metadata for type role, errors otherwise
        """
        if self.type in ["role", "all"] :
            if self._metadata is None:
                meta_path = os.path.join(self.path, self.META_MAIN)
                if os.path.isfile(meta_path):
                    try:
                        f = open(meta_path, 'r')
                        self._metadata = yaml.safe_load(f)
                    except:
                        display.vvvvv("Unable to load metadata for %s" % self.name)
                        return False
                    finally:
                        f.close()

            return self._metadata
        else:
            return {}

    @property
    def galaxy_metadata(self):
        """
        Returns Galaxy Content metadata, found in ansible-galaxy.info
        """
        if self._galaxy_metadata is None:
            gmeta_path = os.path.join(self.path, self.GALAXY_FILE)
            if os.path.isfile(gmeta_path):
                try:
                    with open(gmeta_path, 'r') as f:
                        self._galaxy_metadata = yaml.safe_load(f)
                except:
                    display.vvvvv("Unable to load galaxy metadata for %s" % self.name)
                    return False

        return self._galaxy_metadata

    @property
    def install_info(self):
        """
        Returns Galaxy Content install info
        """
        # FIXME: Do we want to have this for galaxy content?
        if self._install_info is None:

            info_path = os.path.join(self.path, self.META_INSTALL)
            if os.path.isfile(info_path):
                try:
                    f = open(info_path, 'r')
                    self._install_info = yaml.safe_load(f)
                except:
                    display.vvvvv("Unable to load Galaxy install info for %s" % self.name)
                    return False
                finally:
                    f.close()
        return self._install_info

    def _write_galaxy_install_info(self):
        """
        Writes a YAML-formatted file to the role's meta/ directory
        (named .galaxy_install_info) which contains some information
        we can use later for commands like 'list' and 'info'.
        """
        # FIXME - unsure if we want this, need to figure it out and if we want it then need to handle
        #

        info = dict(
            version=self.version,
            install_date=datetime.datetime.utcnow().strftime("%c"),
        )
        if not os.path.exists(os.path.join(self.path, 'meta')):
            os.makedirs(os.path.join(self.path, 'meta'))
        info_path = os.path.join(self.path, self.META_INSTALL)
        with open(info_path, 'w+') as f:
            try:
                self._install_info = yaml.safe_dump(info, f)
            except:
                return False

        return True

    def _write_archived_files(self, tar_file, parent_dir, file_name=None):
        """
        Extract and write out files from the archive, this is a common operation
        needed for both old-roles and new-style galaxy content, the main
        difference is parent directory

        :param tar_file: tarfile, the local archive of the galaxy content files
        :param parent_dir: str, parent directory path to extract to
        :kwarg file_name: str, specific filename to extract from parent_dir in archive
        """
        # now we do the actual extraction to the path

        plugin_found = None
        for member in tar_file.getmembers():
            # Have to preserve this to reset it for the sake of processing the
            # same TarFile object many times when handling an ansible-galaxy.yml
            # file
            orig_name = member.name

            # we only extract files, and remove any relative path
            # bits that might be in the file for security purposes
            # and drop any containing directory, as mentioned above
            if member.isreg() or member.issym():
                parts_list = member.name.split(os.sep)

                # filter subdirs if provided
                if self.type != "role":
                    # Check if the member name (path), minus the tar
                    # archive baseir starts with a subdir we're checking
                    # for
                    if file_name:
                        # The parent_dir passed in when a file name is specified
                        # should be the full path to the file_name as defined in the
                        # ansible-galaxy.yml file. If that matches the member.name
                        # then we've found our match.
                        if member.name == os.path.join(parent_dir, file_name):
                            # lstrip self.name because that's going to be the
                            # archive directory name and we don't need/want that
                            plugin_found = parent_dir.lstrip(self.name)

                    elif len(parts_list) > 1 and parts_list[-2] == C.CONTENT_TYPE_DIR_MAP[self.type]:
                        plugin_found = C.CONTENT_TYPE_DIR_MAP[self.type]
                    if not plugin_found:
                        continue

                if plugin_found:
                    # If this is not a role, we don't expect it to be installed
                    # into a subdir under roles path but instead directly
                    # where it needs to be so that it can immediately be used
                    #
                    # FIXME - are galaxy content types namespaced? if so,
                    #         how do we want to express their path and/or
                    #         filename upon install?
                    if plugin_found in parts_list:
                        subdir_index = parts_list.index(plugin_found) + 1
                        parts = parts_list[subdir_index:]
                    else:
                        # The desired subdir has been identified but the
                        # current member belongs to another subdir so just
                        # skip it
                        continue
                else:
                    parts = member.name.replace(parent_dir, "", 1).split(os.sep)

                final_parts = []
                for part in parts:
                    if part != '..' and '~' not in part and '$' not in part:
                        final_parts.append(part)
                member.name = os.path.join(*final_parts)

                if self.type in C.CONTENT_PLUGIN_TYPES:
                    display.display(
                        "-- extracting %s %s from %s into %s" %
                        (self.type, member.name, self.name, os.path.join(self.path, member.name))
                    )
                if os.path.exists(os.path.join(self.path, member.name)) and not getattr(self.options, "force", False):
                    if self.type in C.CONTENT_PLUGIN_TYPES:
                        message = (
                            "the specified Galaxy Content %s appears to already exist." % os.path.join(self.path, member.name),
                            "Use of --force for non-role Galaxy Content Type is not yet supported"
                        )
                        if self._install_all_content:
                            # FIXME - Probably a better way to handle this
                            display.warning(" ".join(message))
                        else:
                            raise AnsibleError(" ".join(message))
                    else:
                        message = "the specified role %s appears to already exist. Use --force to replace it." % self.name
                        if self._install_all_content:
                            # FIXME - Probably a better way to handle this
                            display.warning(message)
                        else:
                            raise AnsibleError(message)

                # Alright, *now* actually write the file
                tar_file.extract(member, self.path)

                # Reset the name so we're on equal playing field for the sake of
                # re-processing this TarFile object as we iterate through entries
                # in an ansible-galaxy.yml file
                member.name = orig_name

        if self.type != "role":
            if not plugin_found:
                raise AnsibleError("Required subdirectory not found in Galaxy Content archive for %s" % self.name)

    def remove(self):
        """
        Removes the specified content from the content path.
        There is a sanity check to make sure there's a meta/main.yml or
        ansible-galaxy.yml file at this path so the user doesn't blow away
        random directories.
        """
        # FIXME - not yet implemented for non-role types
        if self.type == "role":
            if self.metadata:
                try:
                    rmtree(self.path)
                    return True
                except:
                    pass

        else:
            raise AnsibleError("Removing Galaxy Content not yet implemented")

        return False

    def fetch(self, content_data):
        """
        Downloads the archived content from github to a temp location
        """
        if content_data:

            # first grab the file and save it to a temp location
            if "github_user" in content_data and "github_repo" in content_data:
                archive_url = 'https://github.com/%s/%s/archive/%s.tar.gz' % (content_data["github_user"], content_data["github_repo"], self.version)
            else:
                archive_url = self.src

            display.display("- downloading content from %s" % archive_url)

            try:
                url_file = open_url(archive_url, validate_certs=self._validate_certs)
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                data = url_file.read()
                while data:
                    temp_file.write(data)
                    data = url_file.read()
                temp_file.close()
                return temp_file.name
            except Exception as e:
                display.error("failed to download the file: %s" % str(e))

        return False

    def install(self):
        # the file is a tar, so open it that way and extract it
        # to the specified (or default) content directory
        local_file = False

        if self.scm:
            # create tar file from scm url
            tmp_file = GalaxyContent.scm_archive_content(**self.spec)
        elif self.src:
            if os.path.isfile(self.src):
                # installing a local tar.gz
                local_file = True
                tmp_file = self.src
            elif '://' in self.src:
                content_data = self.src
                tmp_file = self.fetch(content_data)
            else:
                api = GalaxyAPI(self.galaxy)
                # FIXME - Need to update our API calls once Galaxy has them implemented
                content_data = api.lookup_role_by_name(self.src)
                if not content_data:
                    raise AnsibleError("- sorry, %s was not found on %s." % (self.src, api.api_server))

                if content_data.get('role_type') == 'APP':
                    # Container Role
                    display.warning("%s is a Container App role, and should only be installed using Ansible "
                                    "Container" % self.name)

                # FIXME - Need to update our API calls once Galaxy has them implemented
                role_versions = api.fetch_role_related('versions', content_data['id'])
                if not self.version:
                    # convert the version names to LooseVersion objects
                    # and sort them to get the latest version. If there
                    # are no versions in the list, we'll grab the head
                    # of the master branch
                    if len(role_versions) > 0:
                        loose_versions = [LooseVersion(a.get('name', None)) for a in role_versions]
                        try:
                            loose_versions.sort()
                        except TypeError:
                            raise AnsibleError(
                                'Unable to compare content versions (%s) to determine the most recent version due to incompatible version formats. '
                                'Please contact the content author to resolve versioning conflicts, or specify an explicit content version to '
                                'install.' % ', '.join([v.vstring for v in loose_versions])
                            )
                        self.version = str(loose_versions[-1])
                    elif content_data.get('github_branch', None):
                        self.version = content_data['github_branch']
                    else:
                        self.version = 'master'
                elif self.version != 'master':
                    if role_versions and str(self.version) not in [a.get('name', None) for a in role_versions]:
                        raise AnsibleError("- the specified version (%s) of %s was not found in the list of available versions (%s)." % (self.version,
                                                                                                                                         self.name,
                                                                                                                                         role_versions))

                tmp_file = self.fetch(content_data)

        else:
            raise AnsibleError("No valid content data found")

        if tmp_file:

            display.debug("installing from %s" % tmp_file)

            if not tarfile.is_tarfile(tmp_file):
                raise AnsibleError("the file downloaded was not a tar.gz")
            else:
                if tmp_file.endswith('.gz'):
                    content_tar_file = tarfile.open(tmp_file, "r:gz")
                else:
                    content_tar_file = tarfile.open(tmp_file, "r")
                # verify the role's meta file

                meta_file = None
                galaxy_file = None
                archive_parent_dir = None
                members = content_tar_file.getmembers()
                # next find the metadata file
                for member in members:
                    if self.META_MAIN in member.name or self.GALAXY_FILE in member.name:
                        # Look for parent of meta/main.yml
                        # Due to possibility of sub roles each containing meta/main.yml
                        # look for shortest length parent
                        meta_parent_dir = os.path.dirname(os.path.dirname(member.name))
                        if not meta_file:
                            archive_parent_dir = meta_parent_dir
                            if self.GALAXY_FILE in member.name:
                                galaxy_file = member
                            else:
                                meta_file = member
                        else:
                            if len(meta_parent_dir) < len(archive_parent_dir):
                                archive_parent_dir = meta_parent_dir
                                meta_file = member
                                if self.GALAXY_FILE in member.name:
                                    galaxy_file = member
                                else:
                                    meta_file = member

                # FIXME: THIS IS A HACK
                #
                # We've determined that this is a legacy role, we're going to
                # change state and re-eval paths for backwards compat with the
                # legacy role type
                if self.type == "all" and meta_file:
                    self._set_type("role")
                    self._set_content_paths(self._orig_path)
                    self._install_all_content = False

                if not archive_parent_dir:
                    # archive_parent_dir wasn't found above when checking for metadata files
                    parent_dir_found = False
                    for member in members:
                        # This is either a new-type Galaxy Content that doesn't have an
                        # ansible-galaxy.yml file and the type desired is specified and
                        # we check parent dir based on the correct subdir existing or
                        # we need to just scan the subdirs heuristically and figure out
                        # what to do
                        if self.type != "all":
                            if self.type_dir in member.name:
                                archive_parent_dir = os.path.dirname(member.name)
                                parent_dir_found = True
                                break
                        else:
                            for plugin_dir in C.CONTENT_TYPE_DIR_MAP.values():
                                if plugin_dir in member.name:
                                    archive_parent_dir = os.path.dirname(member.name)
                                    parent_dir_found = True
                                    break
                            if parent_dir_found:
                                break

                    if not parent_dir_found:
                        if self.type in C.CONTENT_PLUGIN_TYPES:
                            raise AnsibleError("No content metadata provided, nor content directories found for type: %s" % self.type)

                if not meta_file and not galaxy_file and self.type == "role":
                    raise AnsibleError("this role does not appear to have a meta/main.yml file or ansible-galaxy.yml.")
                else:
                    try:
                        if galaxy_file:
                            # Let the galaxy_file take precedence
                            self._galaxy_metadata = yaml.safe_load(content_tar_file.extractfile(galaxy_file))
                        elif meta_file:
                            self._metadata = yaml.safe_load(content_tar_file.extractfile(meta_file))
                        #else:
                        # FIXME - Need to handle the scenario where we "walk the dirs" and place things where they should be
                    except:
                        raise AnsibleError("this role does not appear to have a valid meta/main.yml or ansible-galaxy.yml file.")

                # we strip off any higher-level directories for all of the files contained within
                # the tar file here. The default is 'github_repo-target'. Gerrit instances, on the other
                # hand, does not have a parent directory at all.
                installed = False
                while not installed:
                    if self.type != "all":
                        display.display("- extracting %s %s to %s" % (self.type, self.name, self.path))
                    else:
                        display.display("- extracting all content in %s to content directories" % self.name)

                    try:
                        if self.type == "role" and meta_file and not galaxy_file:
                            # This is an old-style role
                            if os.path.exists(self.path):
                                if not os.path.isdir(self.path):
                                    raise AnsibleError("the specified roles path exists and is not a directory.")
                                elif not getattr(self.options, "force", False):
                                    raise AnsibleError("the specified role %s appears to already exist. Use --force to replace it." % self.name)
                                else:
                                    # using --force, remove the old path
                                    if not self.remove():
                                        raise AnsibleError("%s doesn't appear to contain a role.\n  please remove this directory manually if you really "
                                                        "want to put the role here." % self.path)
                            else:
                                os.makedirs(self.path)


                            self._write_archived_files(content_tar_file, archive_parent_dir)

                            # write out the install info file for later use
                            self._write_galaxy_install_info()
                            installed = True
                        elif galaxy_file:
                            # Parse the ansible-galaxy.yml file and install things
                            # as necessary

                            # FIXME - need to handle the scenario where we want
                            #         all content types defined in the ansible-galaxy.yml file

                            for content in self.galaxy_metadata:
                                # The galaxy_metadata will contain a dict that defines
                                # a section for each content type to be installed
                                # and then a list of types with their deps and src
                                #
                                # FIXME - Link to permanent public spec once it exists
                                #
                                # https://github.com/ansible/galaxy/issues/245
                                # https://etherpad.net/p/Galaxy_Metadata
                                #
                                # Example to install modules with module_utils deps:
                                ########
                                #meta_version: '0.1'  #metadata format version
                                #modules:
                                # - path: playbooks/modules/*
                                # - path: modules/module_b
                                #   dependencies:
                                #     - src: /module_utils
                                # - path: modules/module_c.py
                                #   dependencies:
                                #     - src: namespace.repo_name.module_name
                                #       type: module_utils
                                #     - src: ssh://git@github.com/acme/ansible-example.git
                                #       type: module_utils
                                #       version: master
                                #       scm: git
                                #       path: common/utils/*
                                #- src: namespace.repo_name.plugin_name
                                #       type: action_plugin
                                #######
                                #
                                #
                                # Handle "modules" for MVP, add more types later
                                #
                                # A more generic way would be to do this, but we're
                                # not "there yet"
                                #   if content == self.type_dir:
                                #
                                #   self.galaxy_metadata[content] # General processing
                                if content == "meta_version":
                                    continue
                                elif content == "modules":
                                    self._set_type("module")
                                    self._set_content_paths()
                                    for module in self.galaxy_metadata[content]:
                                        if len(module["path"].split(os.sep)) > 1:
                                            if module["path"].split(os.sep)[-1] in ['/', '*']:
                                                # Handle the glob or designation of entire directory install
                                                self._write_archived_files(content_tar_file, os.path.join(archive_parent_dir, module['path']))
                                                installed = True
                                            else:
                                                self._write_archived_files(
                                                    content_tar_file,
                                                    os.path.join(archive_parent_dir, os.path.dirname(module['path'])),
                                                    file_name=module['path'].split(os.sep)[-1]
                                                )
                                                installed = True

                                        if 'dependencies' in module:
                                            for dep in module['dependencies']:
                                                if 'src' not in dep:
                                                    raise AnsibleError("ansible-galaxy.yml dependencies must provide a src")


                                                dep_content_info = GalaxyContent.yaml_parse(dep['src'])
                                                # FIXME - Should we assume this to be true for module deps?
                                                dep_content_info["type"] = "module_util"

                                                display.display('- processing dependency: %s' % dep_content_info["src"])

                                                # This is an external dep, treat it as such
                                                if dep_content_info["scm"]:
                                                    dep_content = GalaxyContent(self.galaxy, **dep_content_info)
                                                    try:
                                                        installed = dep_content.install()
                                                    except AnsibleError as e:
                                                        display.warning("- dependency %s was NOT installed successfully: %s " % (dep_content.name, str(e)))
                                                        continue
                                                else:
                                                    # Local dep, just install it
                                                    self._set_type("module_util")
                                                    self._set_content_paths()
                                                    if len(dep["src"].split(os.sep)) > 1:
                                                        if dep["src"].split(os.sep)[-1] in ['/', '*']:
                                                            # Handle the glob or designation of entire directory install
                                                            self._write_archived_files(content_tar_file, os.path.join(archive_parent_dir, dep['src']))
                                                            installed = True
                                                        else:
                                                            self._write_archived_files(
                                                                content_tar_file,
                                                                os.path.join(archive_parent_dir, os.path.dirname(dep['src'])),
                                                                file_name=dep['src'].split(os.sep)[-1]
                                                            )
                                                            installed = True


                                else:
                                    # FIXME - add more types other than module here
                                    raise AnsibleError("ansible-galaxy.yml install not yet supported for type %s" % self.type)

                        elif not meta_file and not galaxy_file:
                            # No meta/main.yml found so it's not a legacy role
                            # and no galaxyfile found, so assume it's a new
                            # galaxy content type and attempt to install it by
                            # heuristically walking the directories and install
                            # the appropriate things in the appropriate places

                            if self.type != "all":
                                self._write_archived_files(content_tar_file, archive_parent_dir)
                                installed = True
                            else:

                                # Find out what plugin type subdirs exist in this repo
                                #
                                # This list comprehension will iterate every member entry in
                                # the tarfile, split it's name by os.sep and drop the top most
                                # parent dir, which will be self.name (we don't want it as it's
                                # not needed for plugin types. First make sure the length of
                                # that split and drop of parent dir is length > 1 and verify
                                # that the subdir is infact in CONTENT_TYPE_DIR_MAP.values()
                                #
                                # This should give us a list of valid content type subdirs
                                # found heuristically within this Galaxy Content repo
                                #
                                plugin_subdirs = [
                                    os.path.join(m.name.split(os.sep)[1:])[0]
                                        for m in members
                                            if len(os.path.join(m.name.split(os.sep)[1:])) > 1
                                            and os.path.join(m.name.split(os.sep)[1:])[0] in C.CONTENT_TYPE_DIR_MAP.values()
                                ]

                                if plugin_subdirs:
                                    self._install_all_content = True
                                    for plugin_subdir in plugin_subdirs:
                                        # Set the type, this is neccesary for processing extraction of
                                        # the tarball content
                                        #
                                        # rstrip the letter 's' from the plugin type subdir, this should
                                        # be the type
                                        self._set_type(plugin_subdir.rstrip('s'))
                                        self._set_content_paths(None)
                                        self._write_archived_files(content_tar_file, archive_parent_dir)
                                        installed = True
                                else:
                                    raise AnsibleError("This Galaxy Content does not contain valid content subdirectories, expected any of: %s " % C.CONTENT_TYPES)

                    except OSError as e:
                        error = True
                        if e.errno == errno.EACCES and len(self.paths) > 1:
                            current = self.paths.index(self.path)
                            if len(self.paths) > current:
                                self.path = self.paths[current + 1]
                                error = False
                        if error:
                            raise AnsibleError("Could not update files in %s: %s" % (self.path, str(e)))

                # return the parsed yaml metadata
                display.display("- %s was installed successfully" % str(self))
                if not local_file:
                    try:
                        os.unlink(tmp_file)
                    except (OSError, IOError) as e:
                        display.warning("Unable to remove tmp file (%s): %s" % (tmp_file, str(e)))
                return True

        return False

    @property
    def spec(self):
        """
        Returns content spec info
        {
           'scm': 'git',
           'src': 'http://git.example.com/repos/repo.git',
           'version': 'v1.0',
           'name': 'repo'
        }
        """
        return dict(scm=self.scm, src=self.src, version=self.version, name=self.name)

    @staticmethod
    def scm_archive_content(src, scm='git', name=None, version='HEAD'):
        """
        Archive a Galaxy Content SCM repo locally

        Implementation originally adopted from the Ansible RoleRequirement
        """
        if scm not in ['hg', 'git']:
            raise AnsibleError("- scm %s is not currently supported" % scm)
        tempdir = tempfile.mkdtemp()
        clone_cmd = [scm, 'clone', src, name]
        with open('/dev/null', 'w') as devnull:
            try:
                popen = subprocess.Popen(clone_cmd, cwd=tempdir, stdout=devnull, stderr=devnull)
            except Exception as e:
                raise AnsibleError("error executing: %s" % " ".join(clone_cmd))
            rc = popen.wait()
        if rc != 0:
            raise AnsibleError("- command %s failed in directory %s (rc=%s)" % (' '.join(clone_cmd), tempdir, rc))

        if scm == 'git' and version:
            checkout_cmd = [scm, 'checkout', version]
            with open('/dev/null', 'w') as devnull:
                try:
                    popen = subprocess.Popen(checkout_cmd, cwd=os.path.join(tempdir, name), stdout=devnull, stderr=devnull)
                except (IOError, OSError):
                    raise AnsibleError("error executing: %s" % " ".join(checkout_cmd))
                rc = popen.wait()
            if rc != 0:
                raise AnsibleError("- command %s failed in directory %s (rc=%s)" % (' '.join(checkout_cmd), tempdir, rc))

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tar')
        if scm == 'hg':
            archive_cmd = ['hg', 'archive', '--prefix', "%s/" % name]
            if version:
                archive_cmd.extend(['-r', version])
            archive_cmd.append(temp_file.name)
        if scm == 'git':
            archive_cmd = ['git', 'archive', '--prefix=%s/' % name, '--output=%s' % temp_file.name]
            if version:
                archive_cmd.append(version)
            else:
                archive_cmd.append('HEAD')

        with open('/dev/null', 'w') as devnull:
            popen = subprocess.Popen(archive_cmd, cwd=os.path.join(tempdir, name),
                                     stderr=devnull, stdout=devnull)
            rc = popen.wait()
        if rc != 0:
            raise AnsibleError("- command %s failed in directory %s (rc=%s)" % (' '.join(archive_cmd), tempdir, rc))

        shutil.rmtree(tempdir, ignore_errors=True)
        return temp_file.name

    @staticmethod
    def yaml_parse(content):

        if isinstance(content, string_types):
            name = None
            scm = None
            src = None
            version = None
            if ',' in content:
                if content.count(',') == 1:
                    (src, version) = content.strip().split(',', 1)
                elif content.count(',') == 2:
                    (src, version, name) = content.strip().split(',', 2)
                else:
                    raise AnsibleError("Invalid content line (%s). Proper format is 'content_name[,version[,name]]'" % content)
            else:
                src = content

            if name is None:
                name = GalaxyContent.repo_url_to_content_name(src)
            if '+' in src:
                (scm, src) = src.split('+', 1)

            return dict(name=name, src=src, scm=scm, version=version)

        if 'role' in content:
            name = content['role']
            if ',' in name:
                # Old style: {role: "galaxy.role,version,name", other_vars: "here" }
                # Maintained for backwards compat
                content = GalaxyContent.role_spec_parse(role['role'])
            else:
                del content['role']
                content['name'] = name
        else:
            content = content.copy()

            if 'src'in content:
                # New style: { src: 'galaxy.role,version,name', other_vars: "here" }
                if 'github.com' in content["src"] and 'http' in content["src"] and '+' not in content["src"] and not content["src"].endswith('.tar.gz'):
                    content["src"] = "git+" + content["src"]

                if '+' in content["src"]:
                    (scm, src) = content["src"].split('+')
                    content["scm"] = scm
                    content["src"] = src

                if 'name' not in content:
                    content["name"] = GalaxyContent.repo_url_to_content_name(content["src"])

            if 'version' not in content:
                content['version'] = ''

            if 'scm' not in content:
                content['scm'] = None

        for key in list(content.keys()):
            if key not in VALID_ROLE_SPEC_KEYS:
                content.pop(key)

        return content

    @staticmethod
    def repo_url_to_content_name(repo_url):
        # gets the role name out of a repo like
        # http://git.example.com/repos/repo.git" => "repo"

        if '://' not in repo_url and '@' not in repo_url:
            return repo_url
        trailing_path = repo_url.split('/')[-1]
        if trailing_path.endswith('.git'):
            trailing_path = trailing_path[:-4]
        if trailing_path.endswith('.tar.gz'):
            trailing_path = trailing_path[:-7]
        if ',' in trailing_path:
            trailing_path = trailing_path.split(',')[0]
        return trailing_path

    @staticmethod
    def role_spec_parse(role_spec):
        # takes a repo and a version like
        # git+http://git.example.com/repos/repo.git,v1.0
        # and returns a list of properties such as:
        # {
        #   'scm': 'git',
        #   'src': 'http://git.example.com/repos/repo.git',
        #   'version': 'v1.0',
        #   'name': 'repo'
        # }
        display.deprecated("The comma separated role spec format, use the yaml/explicit format instead. Line that trigger this: %s" % role_spec,
                           version="2.7")

        default_role_versions = dict(git='master', hg='tip')

        role_spec = role_spec.strip()
        role_version = ''
        if role_spec == "" or role_spec.startswith("#"):
            return (None, None, None, None)

        tokens = [s.strip() for s in role_spec.split(',')]

        # assume https://github.com URLs are git+https:// URLs and not
        # tarballs unless they end in '.zip'
        if 'github.com/' in tokens[0] and not tokens[0].startswith("git+") and not tokens[0].endswith('.tar.gz'):
            tokens[0] = 'git+' + tokens[0]

        if '+' in tokens[0]:
            (scm, role_url) = tokens[0].split('+')
        else:
            scm = None
            role_url = tokens[0]

        if len(tokens) >= 2:
            role_version = tokens[1]

        if len(tokens) == 3:
            role_name = tokens[2]
        else:
            role_name = GalaxyContent.repo_url_to_content_name(tokens[0])

        if scm and not role_version:
            role_version = default_role_versions.get(scm, '')

        return dict(scm=scm, src=role_url, version=role_version, name=role_name)

