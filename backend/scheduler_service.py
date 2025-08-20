"""Standalone entry point for running background maintenance jobs.

This module ensures the APScheduler instance defined in :mod:`backend.app` runs
in a dedicated process. Use it for deployments where the web application and
scheduled tasks operate separately, such as containerized environments or
systemd services.

Example (Docker):
    RUN_SCHEDULER=1 python -m backend.scheduler_service

Example (systemd service snippet):
    [Service]
    Environment=RUN_SCHEDULER=1
    ExecStart=/usr/bin/python -m backend.scheduler_service
"""

# Importing ``start_scheduler`` sets up the Flask application and job
# definitions. The function performs a safety check to ensure the scheduler
# only runs when ``RUN_SCHEDULER=1``.
from .app import start_scheduler


def main() -> None:
    """Entry point that starts the background scheduler."""
    start_scheduler()


if __name__ == "__main__":
    main()
