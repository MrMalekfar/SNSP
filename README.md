# VLESS Configuration Studio

A browser-based utility for turning VLESS links into ready-to-use Xray JSON configurations and standalone V2Box profiles.

## Overview

VLESS Configuration Studio is designed as a focused configuration workspace:

**Paste → Review → Generate → Copy / Export**

Advanced controls stay collapsed until they are needed, keeping the primary workflow fast and easy to scan.

## Outputs

### Generated Xray JSON
A complete multi-outbound Xray configuration generated from the current VLESS input and the project's configuration sources.

### Advanced Xray
A standalone advanced profile using the project's fingerprint, Fragment and cipher-suite configuration.

### V2Box Single Profiles
Independent JSON configurations, presented individually so each profile can be copied without relying on a combined array wrapper.

## Configuration workspace

The optional **Configuration workspace** contains:

- Parsed VLESS values
- Local proxy defaults
- Log level
- Outbound sources from `list.json`
- Burst Observatory settings

These controls are intentionally hidden until needed.

## Privacy

The application is intended to run entirely in the browser. The VLESS link and generated configuration are processed client-side by the application; no server-side configuration service is required by the UI.

Use the application only in an environment you trust and avoid sharing credentials or configuration data unnecessarily.

## Outbound sources

Outbound source data is read from `list.json`.

Keep `list.json` valid JSON and preserve the expected field structure when updating it.

## Deployment

The project is suitable for static hosting such as GitHub Pages.

No server runtime is required for the front-end.

### GitHub Pages

1. Push the project to a repository.
2. Open **Settings → Pages**.
3. Select the branch and publishing folder containing `index.html`.
4. Save the Pages configuration.
5. Open the published site and verify that the static assets load correctly.

## Compatibility

The generated configuration is intended for Xray-based workflows and the project's V2Box copy/import workflow.

Actual support for individual Xray features depends on the Xray core and client version consuming the configuration.

A JSON document being syntactically valid does not guarantee feature support in every client.

## Security

This project generates configuration data. It does not establish trust in a server, domain, IP address, certificate or VLESS credential.

Only use endpoints and configuration values from sources you trust.

Advanced transport settings can affect compatibility and connectivity. Always test generated profiles in the target client before relying on them for production traffic.

## Development notes

The main application logic is in `script.js`.

The interface is defined in `index.html`, and presentation is controlled by `style.css`.

When changing the UI, preserve the DOM IDs consumed by `script.js` unless the corresponding application logic is intentionally updated.

## License

No license is assumed by this project. Add the applicable license before public distribution.

## Disclaimer

This project is provided as a configuration and convenience tool. Review generated output before use and comply with applicable laws, service terms and network policies.
