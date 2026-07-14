// IOC search box. Submitting triggers a fresh correlation query.

import { useState } from "react";

interface SearchBarProps {
  onSearch: (ioc: string) => void;
  loading: boolean;
}

export function SearchBar({ onSearch, loading }: SearchBarProps) {
  const [value, setValue] = useState("");

  return (
    <form
      className="searchbar"
      onSubmit={(event) => {
        event.preventDefault();
        onSearch(value);
      }}
    >
      <input
        className="searchbar__input"
        type="text"
        value={value}
        placeholder="Search an IOC — e.g. malicious.example or 203.0.113.10"
        aria-label="Indicator to correlate"
        onChange={(event) => setValue(event.target.value)}
      />
      <button className="searchbar__button" type="submit" disabled={loading}>
        {loading ? "Searching…" : "Correlate"}
      </button>
    </form>
  );
}
