> Working note for the plugin split. Delete this file once you're done
> referring back to it.

# `xo-server-nanokvm` and `xo-server-host-power-manager` also live in `xo-plugins`

Done. Two repos total: `install_xen_orchestra` (this one) and
[`xo-plugins`](https://github.com/acebmxer/xo-plugins) (public, AGPL-3.0),
holding both plugins as top-level folders. Content is identical in both
places — code, version numbers, license, and now the docs too (the plugin
READMEs are worded to be accurate whether you're reading them here or in
`xo-plugins`, so nothing needs to diverge).

`xo-plugins` has `dev` and `main` branches, mirroring this repo's own
workflow: `dev` for in-progress work, `main` for released content only,
promoted via a PR there when you merge this repo's own release PR. This
means unreleased plugin changes never reach `xo-plugins`' `main` early.

## Keeping them in sync

**A plain `git subtree push` does not work here**, and I only found that out
by testing it against throwaway repos before touching the real ones:
`xo-plugins` holds two plugins on the same branch, and `git subtree push`
does a raw ref push of a freshly split, single-plugin history — there's no
way for that to land without clobbering whichever plugin's folder isn't
part of that push. So instead:

- `scripts/plugin-push.sh <plugin-name>` — this repo → `xo-plugins`. Splits
  the plugin's history locally, pulls that split into a temporary clone of
  `xo-plugins` (a real merge, so it only touches that plugin's folder), and
  pushes. Fully automatic, including the commit and push to `xo-plugins`.
- `scripts/plugin-pull.sh <plugin-name>` — `xo-plugins` → this repo. Copies
  the plugin's files from `xo-plugins` over `plugins/<plugin-name>/` here.
  **Does not commit** — it leaves the change for you to review
  (`git status`) and commit yourself.

**Both scripts sync the branch you're currently on** (`dev` here ↔ `dev`
there, `main` ↔ `main`) and refuse to run from anything else, so you can't
accidentally push in-progress work into `xo-plugins`' `main`.

```bash
scripts/plugin-push.sh xo-server-nanokvm
scripts/plugin-pull.sh xo-server-host-power-manager
```

**The push script only sees committed history** — `git subtree split`
works from the last commit, not uncommitted changes, so a plugin edit has
to be committed here before `plugin-push.sh` will pick it up.

Verified working end-to-end against the real repos, both branches, both
plugins, both directions.

## New plugins follow the same workflow

1. Add it to `plugins/<name>/` here, same as today.
2. One-time import into `xo-plugins`, once per branch (`dev` and `main`):
   ```bash
   git subtree split --prefix=plugins/<name> -b tmp-import-<name>
   git clone https://github.com/acebmxer/xo-plugins.git /tmp/xo-plugins-import
   cd /tmp/xo-plugins-import
   git checkout <dev-or-main>
   git remote add source /home/nick/Projects/github/install_xen_orchestra
   git fetch source tmp-import-<name>
   git subtree add --prefix=<name> source tmp-import-<name> -m "Import <name>"
   git push origin <dev-or-main>
   cd -; git branch -D tmp-import-<name>; rm -rf /tmp/xo-plugins-import
   ```
3. From then on, `scripts/plugin-push.sh <name>` / `scripts/plugin-pull.sh <name>`
   work the same as for the first two — nothing plugin-specific about them.

## Docs — done

- `docs/custom-plugins.md` — links the `xo-plugins` repo.
- Plugin `README.md`s — reworded to be accurate in both repos, so nothing
  needs to diverge or be manually reconciled after a sync.
- `CHANGELOG.md` — entry added.
