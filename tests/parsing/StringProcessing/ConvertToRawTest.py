from coalib.parsing.StringProcessing import convert_to_raw
from tests.parsing.StringProcessing.StringProcessingTestBase import (
    StringProcessingTestBase)


class ConvertToRawTest(StringProcessingTestBase):

    def test_convert_to_raw(self):
        # In (input, output) format
        test_data = [
            ("test", "test"),
            ("test_path", "test_path"),
            ("test, path", "test, path"),
            ("test\\ path", "test\\ path"),
            ("test\\path", "test\\\\path"),
            ("test\\\\path", "test\\\\path"),
            ("test\\=path", "test\\=path"),
            ("test=path", "test=path"),
            ("value\\=as\\something", "value\\=as\\\\something")]
        for test in test_data:
            self.assertEqual(convert_to_raw(test[0], ",.=# "), test[1])
