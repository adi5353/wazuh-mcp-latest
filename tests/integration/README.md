# Live integration tests

These tests (`-m integration`) exercise `WazuhClient` and `WazuhIndexer` against
a **real, running Wazuh stack**. They exist to catch the one class of bug that
the mocked unit suite structurally cannot: drift between this server's
assumptions and the actual Wazuh Manager API / Indexer response shapes.

They **skip automatically** when no live backend is reachable, so they never
report a false pass and never fail merely because nothing is running. They are
excluded from the default `pytest` run and only execute when you ask for them
explicitly (`-m integration`) or in the `integration` CI job (push to `main`).

## Run against an existing Wazuh

If you already have a Wazuh deployment, point the env vars at it and run:

```bash
export WAZUH_HOST=https://your-manager:55000
export WAZUH_USER=wazuh-wui
export WAZUH_PASS='...'
export WAZUH_INDEXER_HOST=https://your-indexer:9200
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASS='...'
export WAZUH_VERIFY_SSL=false        # if using self-signed certs

pytest -m integration --no-cov -v
```

Use a **read-only / test** deployment — the tests only read, but never point
them at a production cluster you cannot afford to query.

## Run against a throwaway local stack

The CI job uses the canonical [`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker)
single-node stack. To reproduce locally:

```bash
sudo sysctl -w vm.max_map_count=262144           # required by the Indexer
git clone --depth 1 -b v4.9.2 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d wazuh.manager wazuh.indexer

# default single-node credentials:
export WAZUH_HOST=https://localhost:55000 WAZUH_USER=wazuh-wui WAZUH_PASS='MyS3cr37P450r.*-'
export WAZUH_INDEXER_HOST=https://localhost:9200 WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASS=SecretPassword
export WAZUH_VERIFY_SSL=false

cd -                       # back to this repo
pytest -m integration --no-cov -v

# tear down when done:
#   (cd wazuh-docker/single-node && docker compose down -v)
```

## Extending the suite

Add new contract tests to `test_live_wazuh.py`. Every test must depend on the
`live_config` fixture (so it skips cleanly without a backend) and should assert
on the **response shape the production code relies on**, not just that a call
returned. Mirror the patterns already in that file.
