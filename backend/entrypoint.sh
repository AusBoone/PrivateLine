#!/bin/sh
# Initialize migrations directory on first run
if [ ! -d migrations ]; then
    flask db init
fi

# Apply any pending migrations
flask db upgrade

exec "$@"
