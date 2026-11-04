# Privora Panel 5.0.0-dev.6.83 — Asynchronous Software Jobs & Card Progress

## Purpose

6.83 removes long Software Center, Extensions & Components, MultiPHP, and Smart Preset mutations from the browser request lifetime. The Agent creates typed background software jobs and the panel polls durable in-process job state.

## Live behavior

- Component install/remove returns a job identifier immediately.
- Smart Preset apply returns a job identifier immediately.
- PHP runtime install/remove returns a job identifier immediately.
- Software mutations are serialized by the Agent to avoid overlapping APT/Composer transactions.
- Jobs expose queued, running, complete, and failed states plus progress percentage, phase, message, and error.
- Component and Smart Preset cards show their own native progress bar.
- Temporary PCC/PHP-FPM/API bridge interruptions do not cancel the Agent job; polling reconnects to the running job.
- APT remains isolated through the transient privileged execution boundary.
- Laravel Composer remains isolated and uses `pcre.jit=0` under the hardened Agent security model.

## Safety

The long-running Agent retains its existing hardening. Browser callers cannot submit arbitrary shell/package commands: the job API accepts only typed component, preset, and PHP-runtime operations that are already allow-listed by Privora.

## Rollback

The direct 6.82-to-6.83 development upgrade must validate an exact 6.82 source tree before staging. Live promotion remains atomic and restores the exact previous tree and previous Agent if acceptance fails.
