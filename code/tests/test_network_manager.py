import mock
import unittest

from network_manager.network_manager import main


class TestNetworkManager(unittest.TestCase):

    @unittest.skip("dummy test")
    def test_main(self):
        """Dummy test."""
        main = mock.Mock()
        main.return_value = None
        assert None is main()
