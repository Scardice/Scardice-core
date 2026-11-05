# v1 fixture

A database written by the real encrypted (v1) application, kept exactly as it
was written. It is frozen: the v1 code that produced it is being removed, so it
cannot be regenerated. Do not edit or "refresh" it.

How it was made (2026-11-01, tree before the plaintext event store):

1. Started the application on an empty directory; it created `data/endpoint`
   with new keys.
2. Through `/sd-api/dice/exec`, in groups `UI-Group:2001` and `UI-Group:2002`,
   with players `UI:1002` / `UI:1003`: `.nn`, `.st`, `.log new 第一章`, `.r`,
   `.ra`, a plain line, `.log off`; and one private `.st` from `UI:1001`.
3. With the application stopped, added through the v1 store API: adapter
   secrets `cred-onebot` (two versions) and `cred-discord`, and plugin storage
   `fixture-ext/counter`, `fixture-ext/中文键`, `other-ext/<empty key>`.
4. `VACUUM INTO` produced a single `events.db` without WAL files.

`keys/` holds the throwaway test keys of that run. They protect nothing.

What it does not cover: endpoint projections, moderation (ban list) and
extension-state projections, pending inbox/outbox rows, Story-log intents.
Those classes are checked against a copy of a real database before release.
