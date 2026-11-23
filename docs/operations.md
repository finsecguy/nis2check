## Running on a server

`docker compose up` binds the app to `127.0.0.1:8080`. On a server, set `NIS2_BIND` in `.env` (Compose reads that file when it publishes the port). Use `0.0.0.0` only to expose the app on the network, and only behind a reverse proxy with HTTPS.

Then set:

- `NIS2_SECURE_COOKIES=true`
- `NIS2_BEHIND_PROXY=true`

Restart with `docker compose up -d`.
