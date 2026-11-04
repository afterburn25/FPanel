# Privora Panel 5.0.0-dev.6.42 Recovery Notes

6.42 is a cumulative UI/UX release built on 6.41. It does not weaken or replace the atomic updater/recovery model.

## UI preferences
- Admin preferences are stored in browser local storage under `privora.admin.preferences.v1`.
- Customer preferences are stored under `privora.customer.preferences.v1`.
- If an operator sees an unexpected theme/layout, use **Panel Preferences → Reset defaults** or clear only those Privora UI preference keys.
- These preference values do not affect server services, websites, DNS, mail, databases or account state.

## Navigation recovery
- WHM sidebar categories are progressively enhanced into collapsible groups by `assets/app.js`.
- If JavaScript fails, the underlying permitted navigation buttons remain in the HTML and no server state is changed.
- Command-palette navigation opens the active sidebar category automatically.

## Create Website recovery
- Website provisioning continues to use the existing certified `site-create` API; 6.42 changes presentation and discovered-runtime selection, not the privileged transaction semantics.
- A hosting package is not required to add a website.
- Failure before host mutation leaves the site uncreated; existing site-create duplicate/preflight and inventory invalidation rules remain in force.

## Permission/update invariants
- `/opt/privora-panel.releases` must remain 0755.
- Staged/live directories must remain 0755 and normal release files 0644.
- Required executables remain 0755.
- `privora-panel` must be able to traverse/read panel entry points.
- The updater must verify the signed target VERSION after promotion and before PASS.
