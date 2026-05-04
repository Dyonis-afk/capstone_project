"""Tests for RAG generators - observation fallback logic."""
import pytest
from unittest.mock import MagicMock, patch


class TestObservationFallback:
    """Tests for observation generation with R1 fallback."""

    def test_observation_uses_chat_when_successful(self):
        """Should use fast model (Chat) when it returns good response."""
        from routers.attack_paths.services.rag_generators import generate_observation_rag

        mock_rag = MagicMock()
        mock_rag.query_fast.return_value = {'result': 'A' * 100}  # Long enough response

        finding_context = {
            'domain': 'TEST.LOCAL',
            'query_name': 'Kerberoasting',
            'primary_edge': 'HasSPN',
            'sources': ['USER1'],
            'targets': ['SVC_ACCOUNT'],
            'finding_count': 1,
        }

        result = generate_observation_rag(finding_context, mock_rag)

        mock_rag.query_fast.assert_called_once()
        mock_rag.query.assert_not_called()  # R1 not used
        assert len(result) > 50

    def test_observation_falls_back_to_r1_when_chat_empty(self):
        """Should retry with R1 when Chat returns empty."""
        from routers.attack_paths.services.rag_generators import generate_observation_rag

        mock_rag = MagicMock()
        mock_rag.query_fast.return_value = {'result': ''}  # Empty response
        mock_rag.query.return_value = {'result': 'B' * 100}  # R1 succeeds

        finding_context = {
            'domain': 'TEST.LOCAL',
            'query_name': 'Kerberoasting',
            'primary_edge': 'HasSPN',
            'sources': ['USER1'],
            'targets': ['SVC_ACCOUNT'],
            'finding_count': 1,
        }

        result = generate_observation_rag(finding_context, mock_rag)

        mock_rag.query_fast.assert_called_once()
        mock_rag.query.assert_called_once()  # R1 was used as fallback
        assert len(result) > 50

    def test_observation_falls_back_to_r1_when_chat_too_short(self):
        """Should retry with R1 when Chat returns response < 50 chars."""
        from routers.attack_paths.services.rag_generators import generate_observation_rag

        mock_rag = MagicMock()
        mock_rag.query_fast.return_value = {'result': 'Too short'}  # < 50 chars
        mock_rag.query.return_value = {'result': 'C' * 100}  # R1 succeeds

        finding_context = {
            'domain': 'TEST.LOCAL',
            'query_name': 'Kerberoasting',
            'primary_edge': 'HasSPN',
            'sources': ['USER1'],
            'targets': ['SVC_ACCOUNT'],
            'finding_count': 1,
        }

        result = generate_observation_rag(finding_context, mock_rag)

        mock_rag.query_fast.assert_called_once()
        mock_rag.query.assert_called_once()  # R1 was used as fallback
