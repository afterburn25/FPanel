# Privora Panel 5.0.0-dev.6.2 — Clean Path Recovery

This recovery build fixes a clean-Ubuntu installer failure in `privora_files`:

```
install: cannot create regular file '/usr/local/libexec/privora-agent': No such file or directory
```

The installer now creates `/usr/local/libexec`, `/usr/local/bin`, and `/usr/local/sbin` before installing Privora host executables. The updater and rollback helper apply the same invariant so later upgrades cannot regress on minimal images.

Existing phase journals remain compatible. If phases through `source` are already `done`, rerunning this installer resumes at `privora_files`.
