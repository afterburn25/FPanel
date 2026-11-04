# dev.6.13 live-host reconciliation recovery

For an existing dev.6.x VPS, upload/extract this source and rerun the same installer command:

```bash
PRIVORA_REQUIRE_APP_CATALOG=0 ./install/privora-install.sh \
  --source-dir "$(pwd)" \
  --mode full \
  --channel developer
```

The existing phase journal skips prior completed bootstrap/certification work. The new `live_host_reconcile` phase refreshes the agent and live-host/UI assets and reconciles the running panel.

For a brand-new VPS you may explicitly select the SQL family:

```bash
./install/privora-install.sh --mode full --sql-family mariadb
# or
./install/privora-install.sh --mode full --sql-family mysql
```

Do not attempt an in-place MariaDB↔MySQL replacement on a server that already contains production databases without a migration/backup plan.
