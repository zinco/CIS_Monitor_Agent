import unittest
from unittest.mock import Mock, patch

from datetime import datetime

from app.intelbras_scanner import (IntelbrasScanner, parse_camera_states,
                                   parse_record_modes, parse_recording_states, parse_storage)


class IntelbrasScannerTests(unittest.TestCase):
    def test_storage_marks_partition_error_without_losing_other_disk(self):
        body = "\n".join([
            "list.info[0].Name=/dev/sda", "list.info[0].State=Success",
            "list.info[0].Detail[0].IsError=false",
            "list.info[0].Detail[0].TotalBytes=2147483648",
            "list.info[0].Detail[0].UsedBytes=1073741824",
            "list.info[1].Name=/dev/sdb", "list.info[1].State=Success",
            "list.info[1].Detail[0].IsError=true",
        ])
        disks = parse_storage(body)
        self.assertEqual([disk["status"] for disk in disks], ["ok", "error"])
        self.assertEqual(disks[0]["free_space_mb"], 1024)

    def test_camera_and_recording_states_keep_unknown_distinct(self):
        cameras = parse_camera_states({"states": [
            {"channel": 0, "connectionState": "Connected"},
            {"channel": 1, "connectionState": "Empty"},
        ]})
        recordings = parse_recording_states({"state": [
            {"Main": {"State": 1}}, {"Main": {"State": 0}}, {},
        ]})
        self.assertEqual([item["signal_present"] for item in cameras], [True, None])
        self.assertEqual([item["recording_status"] for item in recordings],
                         ["recording_now", "not_recording", "unknown"])

    @patch("app.intelbras_scanner.requests.post")
    def test_recording_query_is_read_only_state_request(self, post):
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {"state": [{"Main": {"State": 1}}]}
        post.return_value = response
        result = IntelbrasScanner().get_recording_states("192.0.2.10", 80, "user", "secret")
        self.assertEqual(result["channels_recording_now"], 1)
        self.assertIsNone(result["channels_with_recent_recording"])
        self.assertEqual(post.call_args.args[0],
                         "http://192.0.2.10:80/cgi-bin/api/recordManager/getStateAll")
        self.assertEqual(post.call_args.kwargs["json"], {})

    @patch("app.intelbras_scanner.requests.get")
    def test_video_loss_reports_only_explicit_events(self, get):
        get.return_value = Mock(ok=True, status_code=200, text="channels[0]=0\nchannels[1]=3\n")
        result = IntelbrasScanner().get_video_loss_events("192.0.2.10", 80, "user", "secret")
        self.assertEqual(result["channels"], [1, 4])
        self.assertTrue(result["resolved"])

    def test_real_record_mode_format_and_empty_video_loss(self):
        modes = parse_record_modes("table.RecordMode[0].Mode=0\r\n"
                                   "table.RecordMode[0].ModeExtra1=2\r\n"
                                   "table.RecordMode[1].Mode=2\r\n")
        self.assertEqual(modes, {1: 0, 2: 2})
        scanner = IntelbrasScanner()
        scanner._request = Mock(return_value=Mock(ok=True, status_code=200,
                                                   text="Error: No Events"))
        result = scanner.get_video_loss_events("192.0.2.10", 80, "user", "secret")
        self.assertTrue(result["resolved"])
        self.assertEqual(result["channels"], [])

    def test_finder_is_destroyed_after_result(self):
        scanner = IntelbrasScanner()
        replies = iter([
            Mock(ok=True, text="result=08137\n"),
            Mock(ok=True, text="OK\n"),
            Mock(ok=True, text="found=1\nitems[0].EndTime=2026-09-24 08:57:46\n"),
            Mock(ok=True, text="OK\n"),
            Mock(ok=True, text="OK\n"),
        ])
        scanner._request = Mock(side_effect=lambda *args, **kwargs: next(replies))
        found = scanner._find_latest_recording(
            "192.0.2.10", 80, "user", "secret", 1, datetime(2026, 9, 24, 8, 58))
        self.assertEqual(found, datetime(2026, 9, 24, 8, 57, 46))
        actions = [call.kwargs["params"]["action"] for call in scanner._request.call_args_list]
        self.assertEqual(actions, ["factory.create", "findFile", "findNextFile", "close", "destroy"])

    @patch("app.intelbras_scanner.requests.get")
    def test_time_filter_uses_percent_encoded_space_for_legacy_cgi(self, get):
        scanner = IntelbrasScanner()
        scanner._request("192.0.2.10", 80, "user", "secret", "/cgi-bin/mediaFileFind.cgi",
                         params={"action": "findFile", "condition.StartTime": "2026-09-24 08:30:00"})
        params = get.call_args.kwargs["params"]
        self.assertIn("2026-09-24%2008%3A30%3A00", params)
        self.assertNotIn("+", params)

    def test_late_recording_is_confirmed_before_marking_delayed(self):
        scanner = IntelbrasScanner()
        scanner._device_time = Mock(side_effect=[datetime(2026, 9, 24, 9, 0),
                                                 datetime(2026, 9, 24, 9, 0, 20)])
        scanner._request = Mock(return_value=Mock(ok=True, text="table.RecordMode[0].Mode=0\n"))
        scanner._find_latest_recording = Mock(side_effect=[datetime(2026, 9, 24, 8, 55),
                                                           datetime(2026, 9, 24, 8, 55)])
        sleep = Mock()
        result = scanner.get_recent_recordings("192.0.2.10", 80, "user", "secret", sleep=sleep)
        self.assertEqual(result["channels"][0]["recording_status"], "delayed")
        self.assertEqual(result["queries_performed"], 2)
        sleep.assert_called_once_with(20)


if __name__ == "__main__":
    unittest.main()
