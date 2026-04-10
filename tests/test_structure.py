#!/usr/bin/env python3
"""
Hermes P2P - AST-based structural tests.
Verifies code structure (classes, methods, functions) without running libp2p.
"""
import ast
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "hermes_p2p")


def parse_file(filepath):
    """Parse a Python file and return its AST."""
    with open(filepath, "r") as f:
        return ast.parse(f.read(), filename=filepath)


def get_classes(tree):
    """Return all class names defined in the AST."""
    return [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]


def get_functions(tree):
    """Return all function names defined in the AST."""
    return [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]


def get_class_methods(tree):
    """Return {class_name: [method_names]}."""
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            result[node.name] = [m.name for m in node.body if isinstance(m, ast.FunctionDef)]
    return result


class TestCryptoModule(unittest.TestCase):
    """Test hermes_p2p/crypto.py structure."""

    def test_file_exists(self):
        path = os.path.join(SRC_DIR, "crypto.py")
        self.assertTrue(os.path.exists(path), "crypto.py not found")

    def test_syntax_valid(self):
        path = os.path.join(SRC_DIR, "crypto.py")
        tree = parse_file(path)  # raises SyntaxError if invalid
        self.assertIsInstance(tree, ast.Module)

    def test_has_peer_tracker_class(self):
        tree = parse_file(os.path.join(SRC_DIR, "crypto.py"))
        classes = get_classes(tree)
        self.assertIn("PeerTracker", classes)

    def test_peer_tracker_has_required_methods(self):
        tree = parse_file(os.path.join(SRC_DIR, "crypto.py"))
        methods = get_class_methods(tree)
        pt_methods = methods.get("PeerTracker", [])
        # Verify PeerTracker has typical p2p tracking methods
        self.assertTrue(
            any(m in pt_methods for m in ("record_message", "check_rate", "is_replay")),
            f"PeerTracker missing expected methods. Found: {pt_methods}"
        )


class TestIdentityModule(unittest.TestCase):
    """Test hermes_p2p/identity.py structure."""

    def test_file_exists(self):
        path = os.path.join(SRC_DIR, "identity.py")
        self.assertTrue(os.path.exists(path))

    def test_syntax_valid(self):
        path = os.path.join(SRC_DIR, "identity.py")
        tree = parse_file(path)
        self.assertIsInstance(tree, ast.Module)

    def test_has_identity_class(self):
        tree = parse_file(os.path.join(SRC_DIR, "identity.py"))
        classes = get_classes(tree)
        self.assertIn("Identity", classes)

    def test_identity_class_has_generate(self):
        tree = parse_file(os.path.join(SRC_DIR, "identity.py"))
        methods = get_class_methods(tree)
        id_methods = methods.get("Identity", [])
        self.assertIn("generate", id_methods,
                      f"Identity missing 'generate' method. Found: {id_methods}")


class TestMessageModule(unittest.TestCase):
    """Test hermes_p2p/message.py structure."""

    def test_file_exists(self):
        path = os.path.join(SRC_DIR, "message.py")
        self.assertTrue(os.path.exists(path))

    def test_syntax_valid(self):
        tree = parse_file(os.path.join(SRC_DIR, "message.py"))
        self.assertIsInstance(tree, ast.Module)

    def test_has_secure_message_class(self):
        tree = parse_file(os.path.join(SRC_DIR, "message.py"))
        classes = get_classes(tree)
        self.assertIn("SecureMessage", classes)

    def test_secure_message_has_encrypt_decrypt(self):
        tree = parse_file(os.path.join(SRC_DIR, "message.py"))
        methods = get_class_methods(tree)
        sm_methods = methods.get("SecureMessage", [])
        self.assertTrue(
            any("encrypt" in m.lower() for m in sm_methods),
            f"SecureMessage missing 'encrypt' method. Found: {sm_methods}"
        )
        self.assertTrue(
            any("decrypt" in m.lower() for m in sm_methods),
            f"SecureMessage missing 'decrypt' method. Found: {sm_methods}"
        )


class TestNodeModule(unittest.TestCase):
    """Test hermes_p2p/node.py structure."""

    def test_file_exists(self):
        path = os.path.join(SRC_DIR, "node.py")
        self.assertTrue(os.path.exists(path))

    def test_syntax_valid(self):
        tree = parse_file(os.path.join(SRC_DIR, "node.py"))
        self.assertIsInstance(tree, ast.Module)

    def test_has_hermes_node_class(self):
        tree = parse_file(os.path.join(SRC_DIR, "node.py"))
        classes = get_classes(tree)
        self.assertIn("HermesNode", classes)

    def test_hermes_node_has_key_p2p_methods(self):
        tree = parse_file(os.path.join(SRC_DIR, "node.py"))
        methods = get_class_methods(tree)
        node_methods = methods.get("HermesNode", [])
        # HermesNode uses different naming conventions
        # Look for common p2p patterns: pubkey, peers, topic, room, multiaddr
        patterns = ["peer", "topic", "room", "multiaddr", "pubkey", "connect"]
        found = [m for m in node_methods if any(p in m.lower() for p in patterns)]
        self.assertGreater(
            len(found), 1,
            f"HermesNode missing key P2P methods. Found: {node_methods}"
        )


class TestCliModule(unittest.TestCase):
    """Test cli.py structure."""

    def test_syntax_valid(self):
        path = os.path.join(PROJECT_ROOT, "cli.py")
        tree = parse_file(path)
        self.assertIsInstance(tree, ast.Module)

    def test_has_main_or_cli_function(self):
        tree = parse_file(os.path.join(PROJECT_ROOT, "cli.py"))
        functions = get_functions(tree)
        has_entry = any(
            f in functions for f in ("main", "cli", "run", "interactive", "__main__")
        )
        self.assertTrue(has_entry, f"cli.py missing entry point function. Found: {functions}")


class TestAllModulesImportable(unittest.TestCase):
    """Verify all modules have valid Python syntax (can be compiled)."""

    def test_all_python_files_syntax(self):
        """All .py files in hermes_p2p should parse without syntax errors."""
        src_files = [
            os.path.join(SRC_DIR, f)
            for f in os.listdir(SRC_DIR)
            if f.endswith(".py") and not f.startswith("__")
        ]
        errors = []
        for filepath in src_files:
            try:
                parse_file(filepath)
            except SyntaxError as e:
                errors.append(f"{os.path.basename(filepath)}: {e}")
        self.assertEqual([], errors, f"Syntax errors found: {errors}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
