---
name: init
description: Scaffold a project-aware .claude/settings.json deny list with cfgaudit
disable-model-invocation: true
---

Bootstrap a hardened `.claude/settings.json` for this project, tailored to the tools it actually uses.

Steps:

1. Get cfgaudit's safe-default baseline as JSON (does not write anything):

   ```
   cfgaudit init --dry-run
   ```

2. Inspect the project to infer which command categories should be restricted. Look at files such as package.json, Makefile, go.mod, Dockerfile, and the CI config to see which toolchains are in use — and, just as important, which are NOT (a project that never uses Kubernetes should deny kubectl; one that never deploys cloud infra should deny the relevant CLIs).

3. Merge the baseline with project-specific deny entries you inferred. Keep the credential, key, cloud, and SSH read-deny entries from the baseline unchanged — they are what make the file pass cfgaudit's own policy rules.

4. Show the user the proposed deny list and confirm before writing. On confirmation, write `.claude/settings.json` (create the .claude directory if needed). If the file already exists, do not overwrite it — offer to merge instead.

5. Verify the result:

   ```
   cfgaudit .
   ```

   The generated file should report zero permission-policy findings. Report the outcome to the user.
