# Background Scheduler

The backend uses [APScheduler](https://apscheduler.readthedocs.io/) to perform
periodic maintenance tasks such as removing expired messages and pruning stale
push notification tokens. These jobs **must** run in exactly one process to
avoid duplicated work.

## Running the scheduler

1. Build or configure a Python environment with the backend's dependencies.
2. Set the environment variable `RUN_SCHEDULER=1` to acknowledge that this
   process is responsible for running the scheduler.
3. Execute the dedicated entry point:

   ```bash
   RUN_SCHEDULER=1 python -m backend.scheduler_service
   ```

   The command imports the Flask application, registers all scheduled jobs and
   starts the scheduler. It exits with an error if `RUN_SCHEDULER` is missing to
   prevent accidental startup.

## Deployment options

### Separate container

When deploying with containers, create a small service that only runs the
scheduler:

```yaml
dependencies:
  backend:
    image: privatelinedocker/backend
  scheduler:
    image: privatelinedocker/backend
    command: python -m backend.scheduler_service
    environment:
      RUN_SCHEDULER: "1"
```

### systemd service

For bare-metal deployments, a systemd unit keeps the scheduler alive:

```ini
[Unit]
Description=PrivateLine background scheduler
After=network.target

[Service]
Type=simple
Environment=RUN_SCHEDULER=1
ExecStart=/usr/bin/python -m backend.scheduler_service
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable the service with `systemctl enable --now privatelinescheduler`.

## Notes

The web application (`python backend/app.py`) does **not** start the scheduler.
Running multiple scheduler instances simultaneously can result in redundant
cleanup operations or race conditions. Always ensure that only one process sets
`RUN_SCHEDULER=1`.
