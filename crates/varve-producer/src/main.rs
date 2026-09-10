//! `varve-producer` — assemble, sign and publish a layer (REQ-PRODUCER-002).
//!
//! A SEPARATE binary from `varve`, deliberately. `varve` contacts no network,
//! and that claim is load-bearing in `varve docs air-gap` and the threat
//! model; this program fetches releases, verifies signatures over the network
//! and pushes to a registry. Keeping them apart keeps that claim true.

use clap::{CommandFactory, Parser};
use varve_producer::cli::{Cli, Cmd};
use varve_producer::{
    asset, binfmt, deposit, docs, forge::Forge, gh::CommandRunner, immutable, ingest, nextlayer,
    orchestrate, plan, registry, scan, source,
};

/// `GH_HOST` is what `gh` itself uses to target an instance, so varve reads
/// the same variable rather than inventing a second one.
fn forge_from_env() -> Forge {
    Forge::from_env(
        std::env::var("GH_HOST").ok().as_deref(),
        std::env::var("VARVE_OIDC_ISSUER").ok().as_deref(),
    )
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Plan {
            manifest,
            platforms,
        } => {
            let text = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", manifest.display()))?;
            let m = varve_core::layerspec::parse_layer_manifest(&text)?;
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let items = plan::plan(&m, &refs)?;
            let rels = plan::releases(&items);
            println!(
                "{} payload(s) from {} release(s), realm '{}'",
                items.len(),
                rels.len(),
                m.realm.name
            );
            let unverified = rels
                .iter()
                .filter(|(repo, _)| {
                    items
                        .iter()
                        .any(|i| &i.repo == repo && i.unverified_reason.is_some())
                })
                .count();
            if unverified > 0 {
                println!("{unverified} release(s) carry NO proof of origin (opt-in recorded)");
            }
            for i in &items {
                println!(
                    "  {:<14} {:<24} {:<26} {}{}",
                    i.name,
                    i.repo,
                    i.platform.as_deref().unwrap_or("(portable)"),
                    i.asset,
                    if i.unverified_reason.is_some() {
                        "  [unverified]"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        Cmd::Deposit {
            manifest,
            stage: stage_root,
            layer,
            counter,
            platforms,
            previous,
            present_digests,
        } => {
            let forge = forge_from_env();
            let text = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", manifest.display()))?;
            let m = varve_core::layerspec::parse_layer_manifest(&text)?;
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let planned = plan::plan(&m, &refs)?;

            let prev = match &previous {
                Some(p) => deposit::previous_from_spec(&std::fs::read_to_string(p)?)?,
                None => Default::default(),
            };
            let present = match &present_digests {
                Some(p) => deposit::parse_present_digests(&std::fs::read_to_string(p)?),
                None => Default::default(),
            };
            let optins =
                ingest::parse_optins(&std::env::var("UNVERIFIED_INGEST").unwrap_or_default());

            let downloads = stage_root.join("downloads");
            let scratch = stage_root.join("extract");
            let src = source::GhSource::new(source::Spawn, forge.clone(), &downloads);
            eprintln!(
                "assembling {} payload(s) for realm '{}' from {}",
                planned.len(),
                m.realm.name,
                forge.host
            );
            // Carry-forward, ACTED ON (REQ-REUSEBLOB-001). The earlier design
            // wanted a spec entry naming a digest instead of a path, so the
            // deposit would reference a blob it never held; that was abandoned
            // because a layout missing its blobs is not the artifact of record
            // it gets uploaded as. The bytes come from the DESTINATION
            // REGISTRY instead — which clause 4 of REQ-CARRYFORWARD-001
            // already requires to hold them before reuse is permitted, so the
            // check that makes reuse safe and the source that makes it
            // possible are the same check.
            //
            // The saving is smaller than first claimed and worth stating
            // plainly: not zero bytes, but one host instead of four upstream
            // CDNs, no upstream rate limits, and no re-verification of an
            // unchanged upstream release.
            //
            // The registry comes from the MANIFEST, never a literal — the same
            // rule the deposit workflow follows, so there is one place the
            // realm is defined.
            let reuse_repo = m.realm.registry.trim_start_matches("oci://").to_string();
            let reuse_dir = stage_root.join("reused");
            std::fs::create_dir_all(&reuse_dir)?;
            let reuse_blob = |digest: &str| -> Option<Vec<u8>> {
                let out = reuse_dir.join(digest.replace(':', "-"));
                registry::fetch_blob(&source::Spawn, &reuse_repo, digest, &out)
            };
            let present_check = |digest: &str| present.contains(digest);
            let resolved = orchestrate::run(
                &src,
                &forge,
                &planned,
                &prev,
                &optins,
                &present_check,
                &reuse_blob,
            )?;

            // A payload the layer does not carry on some platform is reported
            // by name. An operator reading a shorter list than they expected
            // should not have to work out which entry went missing.
            for note in deposit::omitted(&planned, &resolved) {
                eprintln!("note: {note}");
            }

            let mut tools = Vec::with_capacity(resolved.len());
            for r in &resolved {
                // Two names, not one (REQ-PAYLOADID-001). `binary` is the
                // executable inside the archive; the plan's `name` is what the
                // payload is CALLED in the layer. They are usually equal, which
                // is why one variable served both until a repository needed to
                // contribute two payloads — at which point every entry from
                // that repo wanted the same deposited name and collided.
                let bin = m
                    .tools
                    .iter()
                    .find(|t| t.name == r.plan.name)
                    .and_then(|t| t.binary.clone())
                    .unwrap_or_else(|| r.plan.name.clone());
                let deposited = r.plan.name.clone();
                let version = asset::bare_version(&r.plan.version).to_string();
                // The same function the downloader used, not a second copy
                // of the convention.
                let dl = source::release_dir(&downloads, &r.plan.repo, &r.plan.version);
                tools.push(deposit::stage_one(
                    &source::Spawn,
                    r,
                    &version,
                    &stage_root,
                    &dl,
                    &scratch,
                    deposit::Names {
                        deposited: &deposited,
                        binary: &bin,
                    },
                )?);
            }

            let spec = deposit::describe(&layer, &m.realm.channel, counter, tools);
            // render() re-parses with varve's own parser and refuses a spec
            // `varve deposit` could not read — before the signing step, not
            // during it.
            let rendered = spec.render()?;
            let out = stage_root.join("deposit-spec.toml");
            std::fs::write(&out, &rendered)?;
            println!("{}", out.display());
            eprintln!(
                "{} payload(s) staged, {} carried forward",
                spec.tools.len(),
                resolved
                    .iter()
                    .filter(|r| matches!(
                        r.decision,
                        varve_producer::carryforward::Decision::Reuse { .. }
                    ))
                    .count()
            );
            Ok(())
        }
        Cmd::Scan { manifest, format } => {
            let json = match format.as_deref() {
                None | Some("text") => false,
                Some("json") => true,
                Some(other) => {
                    eprintln!("error: unknown --format `{other}` (expected `json` or `text`)");
                    std::process::exit(2);
                }
            };
            let text = std::fs::read_to_string(&manifest)?;
            let m = varve_core::layerspec::parse_layer_manifest(&text)?;

            // Through the FORGE, so `GH_HOST` reaches every lookup. The first
            // version of this loop lived here and passed an empty environment,
            // which silently targeted github.com whatever the forge said. On an
            // enterprise instance that fails everywhere — or, worse, succeeds
            // against a same-named repository on the public forge.
            let forge = forge_from_env();
            let answers = scan::latest_releases(&source::Spawn, &forge, &m);

            match scan::compare(&m, &answers) {
                Ok(moved) => {
                    if json {
                        let out: Vec<_> = moved
                            .iter()
                            .map(|x| {
                                serde_json::json!({
                                    "name": x.name, "repo": x.repo,
                                    "pinned": x.pinned, "latest": x.latest,
                                    "payload_version": x.payload_version,
                                    "auto_bumpable": x.auto_bumpable(),
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::json!({ "command": "scan", "moved": out,
                                                "count": moved.len() })
                        );
                    } else if moved.is_empty() {
                        println!("nothing moved");
                    } else {
                        for x in &moved {
                            // A hub payload is marked, because it must not be
                            // bumped by anything that is not reading upstream's
                            // release notes.
                            let note = match &x.payload_version {
                                Some(v) => format!("\t(hub: payload {v}, NOT auto-bumpable)"),
                                None => String::new(),
                            };
                            println!("{}\t{}\t{}{}", x.name, x.pinned, x.latest, note);
                        }
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Docs {
            topic,
            grep,
            coverage,
            strict,
            format,
        } => {
            let json = match format.as_deref() {
                None | Some("text") => false,
                Some("json") => true,
                Some(other) => {
                    eprintln!("error: unknown --format `{other}` (expected `json` or `text`)");
                    std::process::exit(2);
                }
            };
            if topic.as_deref() == Some("check") && coverage {
                let gaps = docs::coverage_gaps(&Cli::command());
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "command": "docs", "undocumented": gaps })
                    );
                } else if gaps.is_empty() {
                    println!(
                        "docs coverage: OK — {} subcommand(s) documented, {} topic(s)",
                        Cli::command().get_subcommands().count(),
                        docs::topics().len()
                    );
                } else {
                    for g in &gaps {
                        eprintln!("undocumented subcommand: {g}");
                    }
                }
                if strict && !gaps.is_empty() {
                    std::process::exit(1);
                }
                return Ok(());
            }
            if let Some(q) = grep {
                for t in docs::grep(&q) {
                    println!("{:<16} {}", t.slug, t.title);
                }
                return Ok(());
            }
            match topic {
                None => {
                    if json {
                        let list: Vec<_> = docs::topics()
                            .iter()
                            .map(|t| serde_json::json!({"slug": t.slug, "title": t.title}))
                            .collect();
                        println!("{}", serde_json::json!({"topics": list}));
                    } else {
                        print!("{}", docs::render_list());
                    }
                }
                Some(slug) => match docs::find(&slug) {
                    Some(t) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({"slug": t.slug, "title": t.title, "body": t.body})
                            );
                        } else {
                            print!("{}", t.body);
                        }
                    }
                    None => {
                        eprintln!("error: no topic {slug:?}. `varve-producer docs` lists them.");
                        std::process::exit(2);
                    }
                },
            }
            Ok(())
        }
        Cmd::NextLayer { repo, line, format } => {
            let json = match format.as_deref() {
                None | Some("text") => false,
                Some("json") => true,
                Some(other) => {
                    eprintln!("error: unknown --format `{other}` (expected `json` or `text`)");
                    std::process::exit(2);
                }
            };
            let line = line.unwrap_or_else(nextlayer::current_line);
            let runner = source::Spawn;

            // The listing must be READ, not inferred. A registry that cannot
            // answer stops this: guessing an id here is signed by whatever runs
            // next, with nobody in between.
            let d = runner.run("oras", &registry::tags_argv(&repo), &[]);
            if d.code == 127 {
                eprintln!("error: oras is not on PATH — cannot read the published record");
                std::process::exit(1);
            }
            if !d.ok() {
                eprintln!(
                    "error: could not list the tags of {repo}: {}\n\
                     Refusing to derive a layer id from a record this program could not read.",
                    d.stderr.trim()
                );
                std::process::exit(1);
            }
            let tags = registry::parse_tags(&d.stdout);

            let layer = match nextlayer::next_layer_id(&tags, &line) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };

            let counter = match nextlayer::highest_published(&tags, &line) {
                None => nextlayer::next_counter(None),
                Some((highest, _)) => {
                    let m =
                        runner.run("oras", &registry::fetch_manifest_argv(&repo, &highest), &[]);
                    if !m.ok() {
                        eprintln!("error: could not fetch the manifest of {highest}");
                        std::process::exit(1);
                    }
                    let digest = match nextlayer::baseline_digest(&m.stdout, &highest) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let tmp = std::env::temp_dir()
                        .join(format!("varve-baseline-{}", digest.replace(':', "-")));
                    let Some(bytes) = registry::fetch_blob(&runner, &repo, &digest, &tmp) else {
                        eprintln!("error: could not fetch the baseline line-status of {highest}");
                        std::process::exit(1);
                    };
                    let _ = std::fs::remove_file(&tmp);
                    match nextlayer::counter_in_envelope(&bytes, &highest) {
                        Ok(c) => nextlayer::next_counter(Some(c)),
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            };

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "next-layer", "line": line,
                        "layer": layer, "counter": counter
                    })
                );
            } else {
                println!("{layer}\t{counter}");
            }
            Ok(())
        }
        Cmd::PublishCheck {
            repo,
            layer,
            digest,
            replace_published,
            format,
        } => {
            // An unvalidated --format silently produced human output for
            // `--format JSON` or `--format yaml`, leaving a workflow's `jq` to
            // discover it downstream. Unknown values exit 2, per the CLI
            // conventions for a bad flag.
            let json = match format.as_deref() {
                None | Some("text") => false,
                Some("json") => true,
                Some(other) => {
                    eprintln!("error: unknown --format `{other}` (expected `json` or `text`)");
                    std::process::exit(2);
                }
            };
            let digest = match immutable::parse_digest(&digest) {
                Ok(d) => d,
                Err(why) => {
                    eprintln!("error: --digest {why}");
                    std::process::exit(2);
                }
            };
            let existing = registry::lookup(&source::Spawn, &repo, &layer)?;
            let verdict = immutable::decide(&existing, &digest);
            let (state, publish, refusal) = match &verdict {
                immutable::Verdict::Publish => ("publish", true, None),
                immutable::Verdict::AlreadyPublished => ("already-published", false, None),
                immutable::Verdict::WouldReplace { existing, incoming } => (
                    "would-replace",
                    replace_published,
                    Some(immutable::Refusal {
                        layer: layer.clone(),
                        existing: existing.clone(),
                        incoming: incoming.clone(),
                    }),
                ),
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "publish-check",
                        "layer": layer,
                        "repo": repo,
                        "verdict": state,
                        "publish": publish,
                        "existing": match &existing {
                            immutable::Existing::At(d) => serde_json::Value::String(d.clone()),
                            immutable::Existing::Absent => serde_json::Value::Null,
                        },
                        "incoming": digest,
                    })
                );
            }
            match (&refusal, replace_published) {
                (Some(r), false) => return Err(anyhow::anyhow!("{r}")),
                (Some(r), true) => {
                    // Loud, and on stderr, so it appears in the log of the run
                    // that did it rather than only in someone's shell history.
                    eprintln!(
                        "::warning::REPLACING published layer {} — was {}, now {}.                          Anyone who already resolved this id keeps the old bytes.",
                        r.layer, r.existing, r.incoming
                    );
                }
                (None, _) => {}
            }
            if !json {
                match &verdict {
                    immutable::Verdict::Publish => {
                        println!("publish        {layer} is not yet published in {repo}")
                    }
                    immutable::Verdict::AlreadyPublished => println!(
                        "already        {layer} is already published in {repo} at {digest} — nothing to do"
                    ),
                    immutable::Verdict::WouldReplace { existing, .. } => {
                        println!("replacing      {layer} was {existing} in {repo}")
                    }
                }
            }
            Ok(())
        }
        Cmd::Arch { file, platform } => {
            let bytes = std::fs::read(&file)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", file.display()))?;
            let format = binfmt::check_platform(&file.display().to_string(), &bytes, &platform)?;
            println!("{:<28} {format:?}", platform);
            Ok(())
        }
        Cmd::Forge => {
            let f = forge_from_env();
            println!("host        {}", f.host);
            println!("oidc issuer {}", f.oidc_issuer);
            if !f.is_public_github() {
                println!(
                    "note        build-provenance availability differs by GitHub \
                     Enterprise Server version; a release publishing a \
                     cosign-signed SHA256SUMS.txt does not depend on it."
                );
            }
            Ok(())
        }
        Cmd::Assets {
            template,
            version,
            available,
            platforms,
        } => {
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let sel = asset::select(&template, &version, &refs, &available)?;
            for (platform, name) in &sel.matched {
                if platform.is_empty() {
                    println!("match  (portable)  {name}");
                } else {
                    println!("match  {platform}  {name}");
                }
            }
            for name in &sel.missing {
                println!("absent {name}");
            }
            // Nothing anywhere is the 2026.08.3 defect: a layer that assembles,
            // signs and publishes while missing a tool it claims to carry.
            if sel.matched.is_empty() {
                anyhow::bail!(
                    "template {template:?} matched no asset on any platform — \
                     the payload would be dropped from a layer that still signs"
                );
            }
            Ok(())
        }
    }
}
