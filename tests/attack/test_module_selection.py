# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import unittest

# Import the function and module definitions from the real source files
from wapitiCore.attack.modules.core import resolve_module_settings, all_modules, common_modules, passive_modules


class TestResolveModuleSettings(unittest.TestCase):
    """
    Unit tests for the resolve_module_settings function.
    This function is responsible for determining the set of active modules
    based on the command-line options provided by the user.
    """

    def test_default_modules_if_none_is_set(self):
        """Tests that 'common' modules are activated by default if no setting is provided."""
        activated_modules = resolve_module_settings(None)
        activated_names = set(activated_modules.keys())
        self.assertSetEqual(activated_names, common_modules)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_select_specific_module(self):
        """Tests selecting a single, specific module."""
        activated_modules = resolve_module_settings("xxe")
        activated_names = set(activated_modules.keys())
        self.assertSetEqual(activated_names, {"xxe"})
        self.assertSetEqual(activated_modules["xxe"], {"GET", "POST"})

    def test_select_all_with_exclusion(self):
        """Tests selecting all modules except a specific one."""
        activated_modules = resolve_module_settings("all,-xxe")
        activated_names = set(activated_modules.keys())
        expected_names = all_modules - {"xxe"}
        self.assertSetEqual(activated_names, expected_names)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_select_common_with_exclusion(self):
        """Tests selecting common modules except a specific one."""
        activated_modules = resolve_module_settings("common,-xss")
        activated_names = set(activated_modules.keys())
        expected_names = common_modules - {"xss"}
        self.assertSetEqual(activated_names, expected_names)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_select_all_with_group_exclusion(self):
        """Tests selecting all modules except an entire group."""
        activated_modules = resolve_module_settings("all,-common")
        activated_names = set(activated_modules.keys())
        expected_names = all_modules - common_modules
        self.assertSetEqual(activated_names, expected_names)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_select_passive_group(self):
        """Tests selecting the 'passive' group of modules."""
        activated_modules = resolve_module_settings("passive")
        activated_names = set(activated_modules.keys())
        self.assertSetEqual(activated_names, passive_modules)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_select_passive_with_exclusion(self):
        """Tests selecting the 'passive' group with an exclusion."""
        activated_modules = resolve_module_settings("passive,-wapp")
        activated_names = set(activated_modules.keys())
        expected_names = passive_modules - {"wapp"}
        self.assertSetEqual(activated_names, expected_names)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_empty_modules_list(self):
        """Tests that an empty string returns no modules."""
        activated_modules = resolve_module_settings("")
        self.assertEqual(len(activated_modules), 0)

    def test_empty_modules_list_bis(self):
        """Tests that an empty string returns no modules."""
        activated_modules = resolve_module_settings(",")
        self.assertEqual(len(activated_modules), 0)

    def test_select_non_existent_module_raises_error(self):
        """Tests that a non-existent module name raises a ValueError."""
        with self.assertRaises(ValueError) as cm:
            resolve_module_settings("nonexistent,xxe")
        self.assertIn("[!] Unable to find a module named nonexistent", str(cm.exception))

    def test_complex_rule(self):
        """Tests a complex rule with mixed inclusions and exclusions."""
        activated_modules = resolve_module_settings("-all,common,+xxe")
        activated_names = set(activated_modules.keys())
        expected_names = common_modules | {"xxe"}
        self.assertSetEqual(activated_names, expected_names)
        for name in activated_names:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_method_restriction_on_single_module(self):
        """Tests that method restriction is applied correctly for a single module."""
        activated_modules = resolve_module_settings("xxe:get")
        self.assertSetEqual(set(activated_modules.keys()), {"xxe"})
        self.assertSetEqual(activated_modules["xxe"], {"GET"})

        activated_modules = resolve_module_settings("xxe:post")
        self.assertSetEqual(set(activated_modules.keys()), {"xxe"})
        self.assertSetEqual(activated_modules["xxe"], {"POST"})

    def test_method_restriction_overrides_group_default(self):
        """Tests that a method restriction on a single module overrides the group default."""
        activated_modules = resolve_module_settings("common,xss:get")
        activated_names = set(activated_modules.keys())
        self.assertSetEqual(activated_names, common_modules)
        self.assertSetEqual(activated_modules["xss"], {"GET"})
        # Other common modules should still be GET, POST
        for name in activated_names - {"xss"}:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})

    def test_method_deactivation(self):
        """Tests that deactivating a specific method works."""
        activated_modules = resolve_module_settings("xxe:get,-xxe:get")
        self.assertSetEqual(set(activated_modules.keys()), set())  # xxe is removed because no methods are left

        activated_modules = resolve_module_settings("common,-xss:get")
        activated_names = set(activated_modules.keys())
        self.assertSetEqual(activated_names, common_modules)
        self.assertSetEqual(activated_modules["xss"], {"POST"})
        # Other common modules should still be GET, POST
        for name in activated_names - {"xss"}:
            self.assertSetEqual(activated_modules[name], {"GET", "POST"})


if __name__ == '__main__':
    unittest.main()