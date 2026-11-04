# Privora Panel 5.0.0-dev.6.20 — Website Account Onboarding

## Problem
The WHM Create Website modal used only the live hosting-account list. On a clean Privora VPS with no provisioned hosting accounts, the required account select rendered completely blank, leaving no useful path forward.

## Fix
- The Website wizard always exposes `+ Create new hosting account` in addition to active existing accounts.
- When no active hosting accounts exist, new-account mode is selected automatically.
- New-account mode collects a validated Linux hosting username and hosting package.
- Submit provisions the hosting account first, then provisions the requested website under that account.
- If account creation succeeds but website creation fails, the account is retained deliberately and the UI tells the administrator exactly what happened so the site can be retried without destructive rollback.
- Existing active hosting accounts remain selectable exactly as before.
- File Manager now displays an explicit `No hosting accounts yet` option instead of a blank selector when there are no accounts.

This UX is part of the core source and therefore applies to future clean installations as well as signed upgrades.
