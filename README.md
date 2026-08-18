# VLESS Configuration Studio

A browser-based utility for turning VLESS links into reviewable, ready-to-use Xray configurations and independent V2Box profiles.

## Workflow

The application is organized around a simple flow:

**Paste → Review → Generate → Copy / Export**

The primary workflow stays focused on the VLESS link. Optional configuration controls remain collapsed until they are needed.

## Outputs

### Generated Xray configuration
A complete multi-outbound Xray configuration built from the current VLESS input, the template settings, and the outbound sources in `list.json`.

### Advanced Xray profile
A 20-outbound profile generated only for TLS VLESS links. Each outbound uses the same UUID, port, TLS, transport, Fragment, and cipher-suite settings; only the `address` changes. Addresses are selected randomly, without replacement, from the `merged` array in `https://github.com/MrMalekfar/Lists/blob/main/merged_lists.json`. The profile uses Burst Observatory plus a `leastLoad` balancer tagged `all`, matching the main Generated Xray routing model.

### V2Box profiles
Independent JSON profiles are presented one at a time so each profile can be copied or imported without depending on a combined array wrapper. The UI shows up to 10 profiles.

## Configuration workspace

The optional **Review & configuration** workspace contains:

- Parsed VLESS values
- Local proxy defaults
- Log level
- Outbound sources loaded from `list.json`
- Burst Observatory settings
- Advanced Xray address generation from the GitHub `merged` list

These controls are hidden by default to keep the main workflow compact.

## Privacy

The application is designed to run entirely in the browser. VLESS input and generated configuration data are processed client-side by the application UI; no server-side configuration service is required.

Use the application only in an environment you trust, and avoid sharing credentials or configuration data unnecessarily.

## Outbound sources

Outbound source data is read from `list.json`. Each entry must provide both `ip` and `sni`.

Keep `list.json` valid JSON and preserve the expected field structure when updating the source list.

## Deployment

The project is suitable for static hosting such as GitHub Pages. No server runtime is required for the front-end.

### GitHub Pages

1. Push the project to a repository.
2. Open **Settings → Pages**.
3. Select the branch and publishing folder containing `index.html`.
4. Save the Pages configuration.
5. Open the published site and verify that the static assets load correctly.

## Compatibility

Generated configurations are intended for Xray-based workflows and the project’s V2Box copy/import workflow. Actual support for individual Xray features depends on the Xray core and client version consuming the configuration.

A syntactically valid JSON document does not guarantee feature support in every client. Review and test generated profiles in the target client before relying on them.

## Security

This project generates configuration data. It does not establish trust in a server, domain, IP address, certificate, or VLESS credential.

Only use endpoints and configuration values from sources you trust. Advanced transport settings can affect compatibility and connectivity.

## Development notes

The main application logic is in `script.js`. The interface is defined in `index.html`, and presentation is controlled by `style.css`.

When changing the UI, preserve the DOM IDs consumed by `script.js` unless the corresponding application logic is intentionally updated.

Before release, validate the generated JSON in the target client and confirm that every output format matches the client’s current import requirements.

## License

No license is assumed by this project. Add the applicable license before public distribution.

## Disclaimer

This project is provided as a configuration and convenience tool. Review generated output before use and comply with applicable laws, service terms, and network policies.
