# ThreatWeave

A threat intelligence knowledge graph. ThreatWeave ingests IOCs (IPs, hashes,
domains, URLs) and cybersecurity reports from multiple sources, normalizes them,
and correlates them in a knowledge graph. Its differentiator over a plain feed
aggregator is finding relationships that exact matching misses — via semantic
similarity with embeddings (a later phase).

## Architecture principle

Structural correlation is **deterministic**: a graph, a JOIN, an edge traversal.
AI is reserved for exactly three ingestion-time jobs:

1. extracting IOCs/TTPs from free text,
2. generating embeddings,
3. writing explanatory narratives on demand.

An LLM is **never** used to correlate IOCs or decide structural relationships —
that is graph logic, and putting AI there would add cost and hallucinations to
data that must be exact. All AI access goes through a single, swappable
`LLMProvider` interface (`extract` / `embed` / `narrate`).

## Stack

- Python 3.11+, FastAPI
- Neo4j (graph), PostgreSQL + pgvector (embeddings, reserved)
- Docker Compose for local infrastructure
- Deterministic IOC extraction via regex/parsers (no AI)
- pytest, ruff, full type hints

## Project layout

```
src/threatweave/
├── config.py            # pydantic-settings, loaded from .env
├── models/              # internal domain models (IOC, Actor, Campaign, graph value objects)
├── parsers/             # deterministic regex IOC parser (+ refanging)
├── connectors/          # ingestion sources (AlienVault OTX)
├── graph/               # GraphStore port + Neo4j and in-memory adapters
├── correlation/         # correlate(): deterministic graph traversal
├── ingest.py            # OTX payload -> graph (Campaign per pulse)
├── llm/                 # LLMProvider interface (defined, not yet implemented)
└── api/                 # FastAPI app and routes
```

## Configuration

All configuration comes from environment variables. Copy the template and fill
in values (never commit `.env`):

```bash
cp .env.example .env
```

Key variables: `NEO4J_*`, `POSTGRES_*`, `OTX_API_KEY`, `LLM_*`, `API_*`,
`GRAPH_BACKEND` (`neo4j` | `memory`) and `SEED_SAMPLE`. See
[.env.example](.env.example) for the full list.

## Install (development)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

## Running

### Option A — no Docker, in-memory demo (fastest)

Runs the API against the in-process graph, seeded from the synthetic sample in
`data/samples/`:

```bash
GRAPH_BACKEND=memory SEED_SAMPLE=true uvicorn threatweave.api.app:app --reload
```

Then query a correlation subgraph:

```bash
curl "http://localhost:8000/api/correlate?ioc=malicious.example&depth=2"
```

You should get a JSON subgraph containing the queried indicator, its sibling
IOCs from the same OTX pulse, and the `Synthetic APT-Test Infrastructure`
campaign node, plus the edges linking them.

### Option B — full stack with Docker (Neo4j + Postgres + API)

```bash
docker compose up --build
```

This starts Neo4j (browser UI at http://localhost:7474, Bolt on 7687), a
pgvector-enabled Postgres (reserved for the embeddings phase), and the API on
`http://localhost:8000`. Populate the graph from OTX by running an ingest against
the running Neo4j (requires a valid `OTX_API_KEY`).

## API

| Method | Path              | Description                                            |
|--------|-------------------|--------------------------------------------------------|
| GET    | `/health`         | Liveness probe.                                        |
| GET    | `/api/correlate`  | Correlation subgraph for an indicator.                 |

`GET /api/correlate?ioc=<value>&depth=<1..4>` — the indicator type is inferred
from the value (IP, domain, hash or URL). Returns `404` if the indicator is not
in the graph. The response is a `{ "nodes": [...], "edges": [...] }` subgraph.

## Testing

The full suite runs offline — no Neo4j, Docker or network required (correlation
is tested against the in-memory store, and the OTX connector against a mocked
transport and a synthetic sample):

```bash
pytest          # run tests
ruff check .    # lint
```

## Data & security

- No secrets in the repo — everything via environment variables.
- `.env` is git-ignored; only `.env.example` (names, no values) is committed.
- Real intelligence data stays out of the repo; `data/samples/` holds only
  synthetic or public data.

## Roadmap

- [x] **Phase 1 — Base graph**: project skeleton, deterministic IOC parsing,
  AlienVault OTX ingestion, Neo4j graph model with an in-memory test backend,
  deterministic correlation and a FastAPI query endpoint. No AI. The `LLMProvider`
  interface and the pgvector infrastructure are defined but not yet implemented.
- [ ] Phase 2 — AI extraction of IOCs/TTPs from free-text reports (`extract`).
- [ ] Phase 3 — Embeddings + pgvector semantic correlation (`embed`).
- [ ] Phase 4 — On-demand explanatory narratives (`narrate`).
