import sys
import os
import shutil
import unittest
from collections import namedtuple

local_script_path = "./gce.py"

try:
    from unittest import mock
except ImportError:
    try:
        import mock
    except ImportError:
        sys.exit("This test requires python mock")

try:
    import libcloud as _libcloud
    from libcloud.compute.drivers import gce as _libcloud_compute_drivers_gce
except ImportError:
    sys.exit("This test requires apache-libcloud python module")

if os.path.isfile("../../../../contrib/inventory/gce.py"):
    abs_script = "../../../../contrib/inventory/gce.py"
elif os.path.isfile("~/ansible/contrib/inventory/gce.py"):
    abs_script = "~/ansible/contrib/inventory/gce.py"
else:
    sys.exit("Could not find gce.py!")

#shutil.copy(abs_script, local_script_path)

Node = namedtuple('Node', 'uuid, name, state, public_ips, private_ips, provider')

class TestScript(object):
    @mock.patch('sys.exit', spec=sys.exit)
    @mock.patch('libcloud.compute.types.Provider', spec=_libcloud.compute.types.Provider)
    @mock.patch('libcloud.compute.drivers.gce.GCENodeDriver', spec=_libcloud_compute_drivers_gce.GCENodeDriver)
    @mock.patch('libcloud.compute.drivers.gce.GCENodeDriver.list_nodes',
                spec=_libcloud_compute_drivers_gce.GCENodeDriver.list_nodes,
                return_value=[[
                        Node('13b1d76d263d745c05b2c6e5234b4f51074f1222', 'awx', 'RUNNING', ['104.196.66.112'], ['10.142.0.7'], 'Google Compute Engine'),
                        Node('2227be803599d2a06e7358928d24031699ac5102', 'cmeyers-341', 'RUNNING', ['35.185.20.141'], ['10.142.0.26'], 'Google Compute Engine'),
                        Node('65c0b74157bcfb1540ee2e2fee9ffd2ff9288585', 'gke-devel-default-pool-1b49cc65-lxj4', 'RUNNING', ['35.231.144.241'], ['10.142.0.6'], 'Google Compute Engine'),
                        Node('2eecb7ffbd44f3785f86c43593d8a26fffed3ebb', 'gke-tower-qe-default-pool-0aa0f212-745b', 'RUNNING', ['34.73.239.41'], ['10.142.0.41'], 'Google Compute Engine'),
                        Node('5687e0f057e8e7de5ed01ba18959c9bb6c772841', 'gke-tower-qe-default-pool-0aa0f212-cnns', 'RUNNING', ['34.73.152.53'], ['10.142.0.42'], 'Google Compute Engine'),
                        Node('c165393cdb0c69d0590327fca01baf194bc42116', 'gke-tower-qe-default-pool-0aa0f212-fm9g', 'RUNNING', ['35.229.91.152'], ['10.142.0.43'], 'Google Compute Engine'),
                        Node('9f148f4b726a6f2b99dfb8c0245e86c52d1a6f83', 'jenkins-ssh-slave-1', 'RUNNING', ['35.196.219.214'], ['10.142.0.11'], 'Google Compute Engine'),
                        Node('23e3e968d9ae442f316219be1edc97554115b84b', 'jm-tower-342-01', 'RUNNING', ['35.196.75.185'], ['10.142.0.25'], 'Google Compute Engine'),
                        Node('a28cee7e4af3e642b8471edae68ce6f891ee71da', 'launched-by-jenkins', 'RUNNING', ['35.231.234.152'], ['10.142.0.10'], 'Google Compute Engine'),
                        Node('9d331bac7e004089e03afedbdc0dcbd40c48f464', 'newinstancetvo', 'RUNNING', ['35.185.28.63'], ['10.142.0.19'], 'Google Compute Engine'),
                        Node('edb50658d9a059dda46e92e0d78ef5d14ec09000', 'production-pootle', 'RUNNING', ['35.190.167.16'], ['10.142.0.4'], 'Google Compute Engine'),
                        Node('a72fbe9d2a868f40b20f03e0a2be7fc9d292b083', 'tower-mockups', 'RUNNING', ['35.190.146.119'], ['10.142.0.2'], 'Google Compute Engine'),
                        Node('21b24f2d2708ff8b9c03fc1f1406f4f70e682928', 'towerapi-testing', 'RUNNING', ['35.196.9.30'], ['10.142.0.12'], 'Google Compute Engine')
                    ]]
                )
    @mock.patch('libcloud.compute.providers.get_driver', spec=_libcloud.compute.providers.get_driver,
        return_value=mock.Mock(spec=_libcloud_compute_drivers_gce.GCENodeDriver))
    def test_gce_script(self, mocked_get_driver, mocked_gcenodedriver, mocked_gcenodedriver_list_nodes, mocked_provider, mocked_sys_exit, capsys):

        try:
            os.environ['GCE_INI_PATH'] = './gce.ini'
            import gce
            gce.GceInventory.parse_cli_args = mock.Mock()
            gce.GceInventory.args = mock.Mock(
                host=None,
                instance_tags=None,
                list=True,
                pretty=False,
                refresh_cache=False
            )
        except ImportError as e:
            sys.exit("Unable to import gce.py: %s" % e)
        gce.GceInventory()
        script_output = capsys.readouterr()
        import q; q.q(script_output)

#os.remove(local_script_path)
