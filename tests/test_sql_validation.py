"""Tests for shallots.ai.query SQL validation."""

from __future__ import annotations

import pytest

from shallots.ai.query import _validate_sql, SQLValidationError


class TestValidateSelectAccepted:
    """Test _validate_sql accepts valid SELECT statements."""

    def test_simple_select(self):
        _validate_sql("SELECT * FROM alerts")

    def test_select_with_where(self):
        _validate_sql("SELECT id, title FROM alerts WHERE severity = 'high'")

    def test_select_with_join(self):
        _validate_sql(
            "SELECT a.id, t.verdict FROM alerts a "
            "JOIN triage t ON a.id = t.alert_id"
        )

    def test_select_count(self):
        _validate_sql("SELECT COUNT(*) FROM alerts")

    def test_select_with_group_by(self):
        _validate_sql("SELECT source, COUNT(*) FROM alerts GROUP BY source")

    def test_select_with_order_and_limit(self):
        _validate_sql("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10")

    def test_select_case_insensitive(self):
        _validate_sql("select * from alerts")

    def test_select_with_leading_whitespace(self):
        _validate_sql("   SELECT * FROM alerts")

    def test_select_with_subquery(self):
        _validate_sql(
            "SELECT * FROM alerts WHERE src_ip IN (SELECT src_ip FROM alerts GROUP BY src_ip HAVING COUNT(*) > 5)"
        )


class TestValidateRejectsInsert:
    """Test _validate_sql rejects INSERT statements."""

    def test_plain_insert(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("INSERT INTO alerts (id) VALUES ('x')")

    def test_insert_select(self):
        """INSERT ... SELECT should be blocked even though it contains SELECT."""
        with pytest.raises(SQLValidationError):
            _validate_sql("INSERT INTO alerts SELECT * FROM alerts")


class TestValidateRejectsUpdate:
    """Test _validate_sql rejects UPDATE statements."""

    def test_plain_update(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("UPDATE alerts SET severity = 'low'")


class TestValidateRejectsDelete:
    """Test _validate_sql rejects DELETE statements."""

    def test_plain_delete(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("DELETE FROM alerts")


class TestValidateRejectsDrop:
    """Test _validate_sql rejects DROP statements."""

    def test_drop_table(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("DROP TABLE alerts")

    def test_drop_index(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("DROP INDEX idx_alerts_timestamp")


class TestValidateRejectsAttachDatabase:
    """Test _validate_sql rejects ATTACH DATABASE."""

    def test_attach_database(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("ATTACH DATABASE '/tmp/evil.db' AS evil")

    def test_detach_database(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("DETACH DATABASE evil")


class TestValidateRejectsSubqueriesWithMutations:
    """Test _validate_sql rejects mutations hidden in subqueries or CTEs."""

    def test_select_with_insert_keyword(self):
        """A SELECT that sneaks in an INSERT keyword should be caught."""
        with pytest.raises(SQLValidationError):
            _validate_sql(
                "SELECT * FROM alerts; INSERT INTO alerts (id) VALUES ('hack')"
            )

    def test_select_with_delete_keyword(self):
        with pytest.raises(SQLValidationError):
            _validate_sql(
                "SELECT * FROM alerts; DELETE FROM alerts"
            )

    def test_select_with_drop_keyword(self):
        with pytest.raises(SQLValidationError):
            _validate_sql(
                "SELECT * FROM alerts; DROP TABLE alerts"
            )

    def test_select_with_create(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("SELECT 1; CREATE TABLE evil (id TEXT)")

    def test_select_with_alter(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("SELECT 1; ALTER TABLE alerts ADD COLUMN evil TEXT")


class TestValidateRejectsPragmaWrites:
    """Test _validate_sql rejects PRAGMA write operations."""

    def test_pragma_journal_mode(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("PRAGMA journal_mode = DELETE")

    def test_pragma_write_embedded_in_select(self):
        """PRAGMA writes hidden after a SELECT should still be caught."""
        with pytest.raises(SQLValidationError):
            _validate_sql("SELECT 1; PRAGMA journal_mode = DELETE")

    def test_pragma_writable_schema(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("PRAGMA writable_schema = ON")


class TestValidateRejectsEmptySQL:
    """Test _validate_sql rejects empty / whitespace-only SQL."""

    def test_empty_string(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("")

    def test_whitespace_only(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("   ")


class TestValidateRejectsTruncateAndReplace:
    """Additional mutation keywords that should be blocked."""

    def test_truncate(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("TRUNCATE TABLE alerts")

    def test_replace_into(self):
        with pytest.raises(SQLValidationError):
            _validate_sql("REPLACE INTO alerts (id) VALUES ('x')")
