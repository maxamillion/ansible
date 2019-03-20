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

class TestScript(unittest.TestCase):
    @mock.patch('libcloud.compute.types.Provider', spec=_libcloud.compute.types.Provider)
    @mock.patch('libcloud.compute.providers.get_driver', spec=_libcloud.compute.providers.get_driver)
    def test_gce_script(self, mocked_get_driver, mocked_provider):
        import q; q.q(mocked_get_driver)
        import q; q.q(mocked_provider)
        try:
            os.environ['GCE_INI_PATH'] = './gce.ini'
            import gce
        except ImportError as e:
            sys.exit("Unable to import gce.py: %s" % e)

#os.remove(local_gce_path)
