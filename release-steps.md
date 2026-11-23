osistack release (prep only). This file records the radicula-style sequence. It does not open, stamp, or ship a release. Do not run the commands below as part of the scaffolding Issue.

Current workspace version is 0.0.0. Cargo `publish = false` is the standing override on workspace.package, inherited by all nine crates. Leave it false until a later, accepted release Issue changes it.

Registry: `perish`, already declared in `.cargo/config.toml` as `sparse+https://cargo.perish.uk/`.

Release authority URL: not present in any existing osistack config, so `[release].authority` is left unset. Lab convention across other products is `https://releases.<ns>.perish.uk` (here that would be `https://releases.osistack.perish.uk`). Confirm that URL before writing it into `plumb.toml` or opening a release.

If targets are declared, v0 is Linux x86_64 GNU only (`x86_64-unknown-linux-gnu`). macOS and Windows are independent Features, not required v0 sub-items.

Nine cargo packages in `[release.cargo].packages`: osistack-crypto, osistack-wire, osistack-http, osistack-h1, osistack-h2, osistack-h3, osistack-tls, osistack-quic, osistack.

Sequence (mirror of radicula; versions are placeholders — use the owed version at the time of a real release):

0. plumb --version; git fetch --tags; main == origin/main; plumb doctor clean; `[release.cargo].packages` lists the nine crates; authority is set only after it is confirmed.
1. plumb release owed
2. plumb release open --version X.Y.Z
3. plumb release stamp --version X.Y.Z-rc.1
4. plumb ship dispatch --marker vX.Y.Z-rc.1 --watch ; plumb ship status --marker vX.Y.Z-rc.1
5. plumb release stamp --version X.Y.Z
6. plumb ship dispatch --marker vX.Y.Z --watch ; plumb ship status --marker vX.Y.Z
7. changelog note dir; plumb changelog --version vX.Y.Z --prove <dir>; plumb depot consign --version vX.Y.Z --kind changelog --dir <dir>
8. plumb release rejoin ; plumb release close --version X.Y.Z ; plumb release owed --version next

Do not run open, stamp, or ship until a later Issue is accepted for that release.
