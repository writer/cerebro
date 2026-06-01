import unittest

from cerebro.v1 import audit_pb2, finding_pb2, tool_pb2


class GeneratedProtoImportTests(unittest.TestCase):
    def test_canonical_contracts_import(self) -> None:
        self.assertEqual(audit_pb2.AuditEvent.DESCRIPTOR.full_name, "cerebro.v1.AuditEvent")
        self.assertEqual(finding_pb2.Finding.DESCRIPTOR.full_name, "cerebro.v1.Finding")
        self.assertEqual(tool_pb2.ToolRegistration.DESCRIPTOR.full_name, "cerebro.v1.ToolRegistration")


if __name__ == "__main__":
    unittest.main()
