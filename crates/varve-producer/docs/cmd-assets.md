# varve-producer assets

Which release assets does a template select, without downloading anything?

```sh
varve-producer assets --template 'rivet-%R-%T.tar.gz' --version v0.36.0
varve-producer assets --template 'toolchain_gnu_%H_arm-zephyr-eabi.tar.xz' \
  --version v1.0.1 --available "$(gh release view v1.0.1 --repo x/y --json assets -q '[.assets[].name]|join(",")')"
```

**The template language is the part of this pipeline that has silently dropped a
tool from a published layer**, so it is inspectable on its own.

## The placeholders

| | expands to | example |
|---|---|---|
| `%V` | the payload's bare version | `0.36.0` |
| `%R` | the release tag as written | `v0.36.0` |
| `%T` | the Rust target triple | `x86_64-unknown-linux-gnu` |
| `%U` | upstream platform tag, **arch first** | `aarch64-macos` |
| `%H` | host platform tag, **os first** | `macos-aarch64` |
| `%P` | the VS Code marketplace platform | `darwin-arm64` |

`%V` and `%R` are the trap: varve's own assets are named `varve-v0.33.0-<triple>`,
so a template using `%V` matches nothing and the payload is reported absent.

They are **two different numbers on a hub** — a repository that ships a payload
whose version is not its release tag. `pulseengine/jess` tags `v0.7.2` and ships
`with-device` at `0.2.2`, so `%R` is `v0.7.2` and `%V` is `0.2.2`. Pass both, or
the preview shows names the deposit will not look for:

```sh
varve-producer assets --template 'with-device-%V-%T.tar.gz' \
  --version 0.2.2 --release v0.7.2
```

`--release` defaults to `--version`, which is right for almost every tool. In a
realm manifest the same distinction is `release =` beside `version =`; `version`
is what the payload IS and what gets signed into the layer, `release` is only
what the forge is asked for.

`%U` and `%H` are the other one. There is no single upstream convention —
bytecodealliance writes `aarch64-macos`, zephyrproject-rtos writes
`macos-aarch64`. Same machine, opposite order, and the wrong one matches
nothing.

A template that matches on NO platform is an error, not a warning: a payload
silently missing from a layer that still signs is how a tool went missing once
already.
