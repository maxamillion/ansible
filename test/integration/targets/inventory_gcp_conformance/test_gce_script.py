import sys
import os
import shutil
import unittest

local_gce_path = "./gce.py"

try:
    from unittest import mock
except ImportError:
    try:
        import mock
    except ImportError:
        sys.exit("This test requires python mock")

try:
    import libcloud as _libcloud
except ImportError:
    sys.exit("This test requires apache-libcloud python module")

if os.path.isfile("../../../../contrib/inventory/gce.py"):
    abs_script = "../../../../contrib/inventory/gce.py"
elif os.path.isfile("~/ansible/contrib/inventory/gce.py"):
    abs_script = "~/ansible/contrib/inventory/gce.py"
else:
    sys.exit("Could not find gce.py!")

#shutil.copy(abs_script, local_gce_path)

class TestScript(object):
    @mock.patch('sys.exit', spec=sys.exit)
    @mock.patch('libcloud.compute.types.Provider', spec=_libcloud.compute.types.Provider)
    @mock.patch('libcloud.compute.providers.get_driver', spec=_libcloud.compute.providers.get_driver)
    def test_gce_script(self, mocked_get_driver, mocked_provider, mocked_sys_exit, capsys):
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

#os.remove(local_gce_path)
