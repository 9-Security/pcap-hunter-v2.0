import sys
import unittest
from unittest.mock import MagicMock

# Mock openai module BEFORE importing app.llm.client
mock_openai_module = MagicMock()
sys.modules["openai"] = mock_openai_module

# Now we can import the client
from app.llm.client import fetch_models


class TestLLMClient(unittest.TestCase):
    def test_fetch_models_success(self):
        # Reset side_effect from previous tests
        mock_openai_module.OpenAI.side_effect = None

        # Setup the mock client returned by OpenAI constructor
        mock_client_instance = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client_instance

        # Mock models.list() response
        mock_model_1 = MagicMock()
        mock_model_1.id = "model-a"
        mock_model_2 = MagicMock()
        mock_model_2.id = "model-b"

        # models.list() returns an iterable
        mock_client_instance.models.list.return_value = [mock_model_1, mock_model_2]

        models = fetch_models("http://test", "key")

        # Verify OpenAI was called with correct args
        mock_openai_module.OpenAI.assert_called_with(base_url="http://test", api_key="key")
        self.assertEqual(models, ["model-a", "model-b"])

    def test_fetch_models_failure(self):
        # Setup exception
        mock_openai_module.OpenAI.side_effect = Exception("Connection error")
        models = fetch_models("http://test", "key")
        self.assertEqual(models, [])  # Should return empty list on error

    def test_generate_report(self):
        # Import inside test to avoid early import issues with mocks
        from app.llm.client import generate_report

        # Reset side_effect
        mock_openai_module.OpenAI.side_effect = None

        # Mock client
        mock_client_instance = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client_instance

        # Mock completions.create
        mock_completion = MagicMock()
        mock_completion.choices = [MagicMock(message=MagicMock(content="Section Content"))]
        mock_client_instance.chat.completions.create.return_value = mock_completion

        # Call generate_report
        context = {"features": {}, "osint": {}, "zeek": {}, "packet_count": 100}
        report = generate_report("http://test", "key", "model-x", context, language="US English")

        # Verify calls - Should be called 7 times (once per section)
        self.assertEqual(mock_client_instance.chat.completions.create.call_count, 7)

        # Verify output concatenation
        # Logic appends "## Title\n\nContent" for each section
        self.assertIn("## Executive Summary", report)
        self.assertIn("Section Content", report)
        # Should have 7 sections * (Header + Content)
        # Just checking basic structure
        self.assertTrue(report.startswith("## Executive Summary"))


if __name__ == "__main__":
    unittest.main()
