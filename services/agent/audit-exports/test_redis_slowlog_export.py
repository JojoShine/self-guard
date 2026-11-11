import unittest
from redis_slowlog_export import convert


class RedisExportTests(unittest.TestCase):
    def test_preserves_command_identity_duration_and_unknown_actor(self):
        entries = [[12, 1794355200, 1500, ["GET", "private-key"], "127.0.0.1:43210", "app"]]
        row = convert(entries, "a" * 40)[0]
        self.assertEqual(row["eventId"], "redis-slowlog:" + "a" * 40 + ":12")
        self.assertEqual(row["execution"]["sql"], '["GET","private-key"]')
        self.assertEqual(row["execution"]["durationMs"], 1.5)
        self.assertFalse(row["userKnown"])
        self.assertNotIn("succeeded", row)
        self.assertNotIn("sqlState", row["execution"])
        self.assertEqual(convert(entries, "a" * 40)[0], row)

    def test_rejects_malformed_or_oversized_sources_without_partial_output(self):
        for entries in ([[[1, 2, 3]]], [[1, 2, -1, ["GET"]]], [[1, 2, 3, ["x" * 32769]]], [[True, 2, 3, ["GET"]]]):
            with self.assertRaises(ValueError):
                convert(entries, "a" * 40)
        with self.assertRaises(ValueError):
            convert([], "invented-id")


if __name__ == "__main__":
    unittest.main()
