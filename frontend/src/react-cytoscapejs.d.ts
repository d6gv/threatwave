// Minimal type shim: react-cytoscapejs ships no type declarations. Covers only
// the props this app uses.
declare module "react-cytoscapejs" {
  import type { Component, CSSProperties } from "react";
  import type cytoscape from "cytoscape";

  interface CytoscapeComponentProps {
    elements: cytoscape.ElementDefinition[];
    stylesheet?: cytoscape.StylesheetStyle[];
    layout?: cytoscape.LayoutOptions;
    cy?: (cy: cytoscape.Core) => void;
    style?: CSSProperties;
    className?: string;
    id?: string;
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}
