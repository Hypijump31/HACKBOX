import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import pytest
from security_toolbox.reporter import Reporter

def test_generate_txt_report(tmp_path):
    reporter = Reporter()
    data = {"scan": {"22": "open"}, "vuln": {22: [{"id": "CVE-2024-0001"}]} }
    output_file = tmp_path / "report.txt"
    reporter.generate_txt(data, str(output_file))
    assert output_file.exists()
    content = output_file.read_text()
    assert "22" in content and "open" in content and "CVE-2024-0001" in content

def test_generate_txt_report_error():
    reporter = Reporter()
    data = {"scan": {}}
    with pytest.raises(Exception):
        reporter.generate_txt(data, "/invalid_path/report.txt")
