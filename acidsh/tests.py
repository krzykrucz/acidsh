import unittest
from acidsh.snapshot import _is_subdir, _get_parent_dir


class TestStringMethods(unittest.TestCase):

    def test_sub_dir(self):
        self.assertTrue(_is_subdir('/home/hector', '/home'))
        self.assertTrue(_is_subdir('/home', '/home'))
        self.assertFalse(_is_subdir('/home', '/home/hector'))

    def test_parent_dir(self):
        self.assertEquals(_get_parent_dir('/home/hector'), '/home')
        self.assertEquals(_get_parent_dir('/home/hector/file'), '/home/hector')
        self.assertEquals(_get_parent_dir('/'), '/')

if __name__ == '__main__':
    unittest.main()