// Application shell wiring search + interactive graph. The node detail panel and
// on-demand narrative are layered on in the next commit.

import { GraphView } from "./components/GraphView";
import { SearchBar } from "./components/SearchBar";
import { useGraph } from "./hooks/useGraph";

export function App() {
  const { graph, selectedId, loading, error, search, expandNode, select } = useGraph();
  const hasGraph = graph.nodes.length > 0;

  return (
    <div className="app">
      <header className="app__header">
        <div>
          <h1 className="app__title">ThreatWeave</h1>
          <p className="app__tagline">Deterministic threat-intelligence graph explorer</p>
        </div>
        <SearchBar onSearch={search} loading={loading} />
      </header>

      {error && <div className="app__error">{error}</div>}

      <main className="app__main">
        {hasGraph ? (
          <GraphView
            graph={graph}
            selectedId={selectedId}
            onSelect={select}
            onExpand={expandNode}
          />
        ) : (
          <div className="app__empty">
            <p>Search an indicator to build its correlation graph.</p>
            <p className="app__hint">
              Try <code>malicious.example</code> or <code>203.0.113.10</code>. Click a
              node to select it, double-click to expand its relationships.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
