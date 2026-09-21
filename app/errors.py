"""Errors that can be safely shown in an assessment report or API response."""


class ScanError(Exception):
    """An expected collection, provider, or validation failure."""
