import unittest
from dm8_export import convert


class ExportTests(unittest.TestCase):
    def test_preserves_identical_events_and_strips_sensitive_fields(self):
        row = ["1", "APP", "", "", "::1", "", "APP", "", "PAYMENT", "104", "Y",
               "private SQL", "private description", "2026-11-02 16:00:00", "mac", "0", "secret parameters"]
        body = ("__COL__".join(row) + "__ROW__") * 2
        output = convert(body, "a" * 64, "DAMENG", "+08:00", {"104": "SELECT"}, "__COL__", "__ROW__")
        self.assertNotEqual(output[0]["EVENT_ID"], output[1]["EVENT_ID"])
        self.assertEqual(output[0]["EVENT_TIMESTAMP"], "2026-11-02T08:00:00+00:00")
        self.assertNotIn("private", str(output))
        self.assertNotIn("secret", str(output))
        self.assertEqual(output, convert(body, "a" * 64, "DAMENG", "+08:00", {"104": "SELECT"}, "__COL__", "__ROW__"))

    def test_rejects_incomplete_or_ambiguous_export(self):
        for body in ("partial", "wrong__ROW__"):
            with self.assertRaises(ValueError):
                convert(body, "a" * 64, "DAMENG", "+08:00", {}, "__COL__", "__ROW__")

    def test_explicit_sql_opt_in_never_exports_bind_parameters(self):
        row = ["1", "APP", "", "", "::1", "", "APP", "", "T", "104", "Y",
               "SELECT 'original'", "private description", "2026-11-02 16:00:00", "mac", "0", "secret bindings"]
        args = ("__COL__".join(row) + "__ROW__", "a" * 64, "DM", "+08:00", {}, "__COL__", "__ROW__")
        result = convert(*args, include_statement=True)
        self.assertEqual(result[0]["SQL_TEXT"], row[11])
        self.assertNotIn("secret", str(result))
        self.assertNotIn("description", str(result))
        row[11] = "x" * 32769
        with self.assertRaises(ValueError):
            convert("__COL__".join(row) + "__ROW__", *args[1:], include_statement=True)


if __name__ == "__main__":
    unittest.main()
