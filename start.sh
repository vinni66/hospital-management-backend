#!/bin/bash

# Apply eventlet monkey patching and start Gunicorn
python -c "import eventlet; eventlet.monkey_patch()"
gunicorn --worker-class eventlet -w 1 app:app