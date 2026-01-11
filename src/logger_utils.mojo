"""Shared logger utilities for consistent test output formatting."""

from time import perf_counter

from logger import Level, Logger


fn default_logger() -> Logger[Level.INFO]:
    """Returns a default INFO logger with source location enabled."""
    return Logger[Level.INFO](source_location=True)


fn log_info(log: Logger[Level.INFO], message: String):
    """Logs an INFO message with a standard timestamp prefix."""
    log.info("[t=", String(perf_counter()), "]", message)


fn log_warning(log: Logger[Level.INFO], message: String):
    """Logs a WARNING message with a standard timestamp prefix."""
    log.warning("[t=", String(perf_counter()), "]", message)
