//! The WIT dependency closure, computed from the packages themselves
//! (REQ-WIT-001 clauses 2 and 4, DD-036).
//!
//! A `wit` payload is exactly ONE WIT package, stored flat under its
//! `namespace:name@version`, in the binary package form `<ns>/<name>/<ver>.wasm`
//! that `wkg`'s local backend reads. Dependencies are never vendored into a
//! payload's slot in the store; the `wit/ + deps/` tree a consumer wants is
//! composed on request, from packages the layer already carries.
//!
//! Composing it needs an answer to "what does this package need?", and there
//! are two places that answer could live. It could be restated in `layer.toml`
//! — and then it is a second list, kept in step with the bytes by hand, which
//! is the drift REQ-WIT-001 exists to remove. Or it can be read out of the
//! signed bytes, which is transcription and cannot disagree with them. This
//! module does the second. Nothing here reads the manifest, and nothing here
//! touches the network: the only inputs are bytes already in the store.
//!
//! WHAT A REFUSAL IS FOR (clause 4). A closure that cannot be completed is an
//! error naming the missing package, never a shortened tree. A `deps/` directory
//! silently missing one package does not fail here — it fails minutes later
//! inside `wit-bindgen` or `cargo-component`, with a message about an interface,
//! and the person reading it has no reason to suspect the layer. So the refusal
//! is the product; the partial tree would be the bug.
//!
//! WHAT THIS MODULE DOES NOT CLAIM. The binary encoding of a WIT package
//! structurally embeds the TYPES of the packages it imports — it has to, since
//! a component type must be self-contained. So the bytes of `acme:app` carry a
//! view of `wasi:io@0.2.0`, and the layer separately carries `wasi:io@0.2.0` as
//! its own payload. This module reads the NAMES out of that embedded view and
//! resolves each one against the layer's own payloads; it does not check that
//! the embedded view and the stored payload agree. That check is worth having
//! and is NOT here: a completed closure says every named package is carried, not
//! that the carried bytes match the view the dependent was built against.
//!
//! One consequence of the same embedding, which surprises on first reading: the
//! names a package carries are the packages its TYPES reach, not only the ones
//! it writes `use` for. A package that uses `acme:left`, which in turn uses
//! `acme:base`, names both. So the closure is mostly present in the root's own
//! bytes already, and the walk's real work is confirming that each named package
//! is one the layer CARRIES — which is what clause 4 is about.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use wit_parser::decoding::{DecodedWasm, decode};

/// The flat key a layer stores one WIT package under: `namespace:name@version`.
///
/// Ordering and equality are on the key TEXT, not on a parsed semver. That is
/// deliberate: semver precedence deliberately ignores build metadata, so
/// `acme:io@1.0.0+a` and `acme:io@1.0.0+b` compare *equal* under it — and those
/// are two distinct payloads at two distinct digests. Collapsing them is exactly
/// the "one name, two sets of bytes" failure the flat store exists to make
/// unrepresentable (REQ-STORE-002), so identity here is the key as written.
///
/// One `String` rather than three, because the key is the identity and the
/// three parts are views of it — and because this type is carried by several
/// error variants, where three allocations' worth of inline width is paid on
/// every `Result` in the module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageIdent {
    key: String,
}

impl PackageIdent {
    /// Build an identifier, refusing anything that could not be a key.
    ///
    /// The three parts become path components in `binary_path`, so they are
    /// validated HERE rather than at the point of use: a `..` or a `/` reaching
    /// a path join is the classic traversal, and a key that cannot be written
    /// down is not a key. Decoded packages always pass — `wit-parser` has
    /// already enforced kebab-case identifiers — so this only ever bites a
    /// hand-written reference.
    pub fn new(
        namespace: impl AsRef<str>,
        name: impl AsRef<str>,
        version: impl AsRef<str>,
    ) -> Result<Self, WitClosureError> {
        let (namespace, name, version) = (namespace.as_ref(), name.as_ref(), version.as_ref());
        let bad = |part: &str, chars: fn(char) -> bool| {
            part.is_empty() || part == "." || part == ".." || !part.chars().all(chars)
        };
        // Namespace and name are WIT identifiers: ASCII alphanumeric and `-`.
        let id_char = |c: char| c.is_ascii_alphanumeric() || c == '-';
        // A version additionally carries `.`, and semver's pre-release `-` and
        // build-metadata `+`. It is kept as written rather than normalised,
        // because a normaliser would be a second opinion about what a package
        // is called, and the package's own bytes are the first.
        let ver_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+');
        if bad(namespace, id_char) || bad(name, id_char) || bad(version, ver_char) {
            return Err(WitClosureError::MalformedRef {
                text: format!("{namespace}:{name}@{version}"),
            });
        }
        Ok(Self {
            key: format!("{namespace}:{name}@{version}"),
        })
    }

    /// The offsets of the two separators. `new` guarantees both exist exactly
    /// once and that no part contains either, so splitting on the first of each
    /// recovers the parts unambiguously.
    fn split(&self) -> (usize, usize) {
        let colon = self.key.find(':').unwrap_or(0);
        let at = self.key.find('@').unwrap_or(self.key.len());
        (colon, at)
    }

    pub fn namespace(&self) -> &str {
        &self.key[..self.split().0]
    }

    pub fn name(&self) -> &str {
        let (colon, at) = self.split();
        &self.key[colon + 1..at]
    }

    pub fn version(&self) -> &str {
        &self.key[self.split().1 + 1..]
    }

    /// The key as written: `namespace:name@version`.
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// Where this package's bytes live in the store: `<ns>/<name>/<ver>.wasm`
    /// (DD-036). Byte-identical placement to what `wkg`'s local backend reads,
    /// which is what makes a later *link* a pointer rather than an export.
    pub fn binary_path(&self) -> String {
        format!(
            "{}/{}/{}.wasm",
            self.namespace(),
            self.name(),
            self.version()
        )
    }
}

impl std::fmt::Display for PackageIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.key)
    }
}

impl std::str::FromStr for PackageIdent {
    type Err = WitClosureError;

    /// Parse `namespace:name@version`. The version is REQUIRED — see
    /// `WitClosureError::Unversioned` for why a flat store has nowhere to put
    /// an unversioned package.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || WitClosureError::MalformedRef {
            text: s.to_string(),
        };
        let (namespace, rest) = s.split_once(':').ok_or_else(malformed)?;
        let (name, version) = rest.split_once('@').ok_or_else(malformed)?;
        // `split_once` takes the FIRST separator, so a second `:` or `@` lands
        // inside a part and is rejected by `new`'s character check rather than
        // silently absorbed.
        Self::new(namespace, name, version).map_err(|_| malformed())
    }
}

/// One stored WIT package: who it is, what it imports, and the digest of the
/// bytes that said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitPackage {
    ident: PackageIdent,
    imports: BTreeSet<PackageIdent>,
    digest: String,
}

impl WitPackage {
    /// Read a binary WIT package.
    ///
    /// Identity comes from the BYTES, never from the file name they arrived
    /// under. A store path is a label a depositor chose; the encoded package
    /// name is what the signature covers, so a mislabelled payload is caught
    /// here instead of becoming a second name for the same thing.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, WitClosureError> {
        let decoded = decode(bytes).map_err(|e| WitClosureError::Undecodable {
            // The error chain matters: the top line is usually "failed to parse
            // WebAssembly module" and the cause is the byte offset.
            detail: format!("{e:#}"),
        })?;
        let (resolve, package_id) = match decoded {
            DecodedWasm::WitPackage(resolve, id) => (resolve, id),
            // A component that happens to carry WIT metadata is not a WIT
            // package, and neither is a bare core module. Both decode cleanly,
            // so refusing them takes an explicit arm.
            DecodedWasm::Component(..) => return Err(WitClosureError::NotAWitPackage),
        };

        let ident = ident_of(&resolve, package_id)?;
        let mut imports = BTreeSet::new();
        for dep in resolve.package_direct_deps(package_id) {
            let dep_ident = ident_of(&resolve, dep)?;
            // A self-edge is not a dependency. `package_direct_deps` reports
            // foreign packages, but guarding costs one line and the failure it
            // would cause is total: a self-edge reads as a cycle, so every
            // closure would refuse.
            if dep_ident != ident {
                imports.insert(dep_ident);
            }
        }

        Ok(Self {
            ident,
            imports,
            digest: hex::encode(Sha256::digest(bytes)),
        })
    }

    pub fn ident(&self) -> &PackageIdent {
        &self.ident
    }

    /// The packages this one names, in key order. Deduplicated: the encoding
    /// reports one foreign package once per reference, and a dependency named
    /// twice is still one dependency.
    pub fn imports(&self) -> &BTreeSet<PackageIdent> {
        &self.imports
    }

    /// Hex SHA-256 of the encoded package. Held so the index can tell "the same
    /// payload offered twice" from "two payloads claiming one name".
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Turn a decoded package's name into a store key, refusing what cannot be one.
fn ident_of(
    resolve: &wit_parser::Resolve,
    id: wit_parser::PackageId,
) -> Result<PackageIdent, WitClosureError> {
    let name = &resolve.packages[id].name;
    let version = name
        .version
        .as_ref()
        .ok_or_else(|| WitClosureError::Unversioned {
            ident: format!("{}:{}", name.namespace, name.name),
        })?;
    PackageIdent::new(&name.namespace, &name.name, version.to_string())
}

/// The WIT packages a layer carries, keyed by identity.
///
/// This is the whole world a closure may be drawn from. There is no fallback
/// and no fetch: a package that is not in here is missing, and missing is a
/// refusal (clause 4). That is what makes the computation offline by
/// construction rather than by configuration.
#[derive(Debug, Clone, Default)]
pub struct PackageIndex {
    by_ident: BTreeMap<PackageIdent, WitPackage>,
}

impl PackageIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a package.
    ///
    /// Offering the SAME bytes twice is fine — a layer may reach this index by
    /// more than one route. Offering DIFFERENT bytes under one identity is
    /// refused, because that is precisely the state flat storage exists to make
    /// unrepresentable: one name, two sets of bytes, both signed, and every
    /// consumer silently getting whichever was inserted first.
    pub fn insert(&mut self, package: WitPackage) -> Result<(), WitClosureError> {
        if let Some(existing) = self.by_ident.get(package.ident())
            && existing.digest() != package.digest()
        {
            return Err(WitClosureError::ConflictingIdentity {
                ident: package.ident().clone(),
                first: existing.digest().to_string(),
                second: package.digest().to_string(),
            });
        }
        self.by_ident.insert(package.ident().clone(), package);
        Ok(())
    }

    /// Decode and add a binary WIT package, returning the identity its own
    /// bytes declared.
    pub fn insert_binary(&mut self, bytes: &[u8]) -> Result<PackageIdent, WitClosureError> {
        let package = WitPackage::from_binary(bytes)?;
        let ident = package.ident().clone();
        self.insert(package)?;
        Ok(ident)
    }

    pub fn get(&self, ident: &PackageIdent) -> Option<&WitPackage> {
        self.by_ident.get(ident)
    }

    pub fn len(&self) -> usize {
        self.by_ident.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ident.is_empty()
    }

    /// Every identity in the index, in key order.
    pub fn idents(&self) -> impl Iterator<Item = &PackageIdent> {
        self.by_ident.keys()
    }
}

/// The transitive dependency closure of `root`, or the reason there is none.
///
/// The result is ordered so that every package appears AFTER everything it
/// imports, with `root` last — a depth-first post-order taking each package's
/// imports in key order. Two properties matter and both are load-bearing:
///
/// * it is DETERMINISTIC. The walk reads only `BTreeSet`/`BTreeMap`, so neither
///   the order packages were inserted in nor a hash seed can reach it. This
///   feeds a signed artifact; two machines that disagree about the order would
///   disagree about the artifact.
/// * deps precede dependents, which is the order a consumer materialising a
///   tree wants, and the order that makes a cycle impossible to express.
///
/// DIAMOND versus CYCLE, which are not the same thing and have been confused
/// here before. A diamond — `top` needs `l` and `r`, both of which need `base`
/// — is an ordinary DAG and entirely legal: `base` is visited once and appears
/// once. A cycle — `a` needs `b` needs `a` — has no valid order at all and is
/// refused. The walk tells them apart by tracking two sets rather than one:
/// `finished` (this package's whole subtree is already emitted; meeting it
/// again is a diamond, so skip) and `path` (this package is an ANCESTOR of
/// where we stand; meeting it again is a cycle). A single "seen" set would call
/// the diamond a cycle or the cycle a diamond, depending on which way it erred.
pub fn closure(
    index: &PackageIndex,
    root: &PackageIdent,
) -> Result<Vec<PackageIdent>, WitClosureError> {
    if index.get(root).is_none() {
        // Distinguished from an incomplete closure on purpose: nothing is
        // missing from a tree that was never begun, and the person who asked
        // for a package the layer does not carry needs to hear that, not a
        // report about a dependency.
        return Err(WitClosureError::RootMissing { root: root.clone() });
    }

    // An explicit stack rather than recursion: the depth of this walk is
    // attacker-controlled in the sense that a layer could carry a very long
    // chain, and a stack overflow is an abort, not a refusal.
    enum Step {
        Enter {
            ident: PackageIdent,
            required_by: Option<PackageIdent>,
        },
        Leave(PackageIdent),
    }

    let mut stack = vec![Step::Enter {
        ident: root.clone(),
        required_by: None,
    }];
    let mut finished: BTreeSet<PackageIdent> = BTreeSet::new();
    // The ancestor chain — a stack, not a set, so a cycle can be REPORTED and
    // not merely detected. `a -> b -> a` is fixable; "there is a cycle" is not.
    let mut path: Vec<PackageIdent> = Vec::new();
    let mut order: Vec<PackageIdent> = Vec::new();

    while let Some(step) = stack.pop() {
        match step {
            Step::Enter { ident, required_by } => {
                if finished.contains(&ident) {
                    continue; // diamond: already emitted, and once is right.
                }
                if let Some(at) = path.iter().position(|p| *p == ident) {
                    let mut cycle: Vec<PackageIdent> = path[at..].to_vec();
                    cycle.push(ident);
                    return Err(WitClosureError::Cycle { path: cycle });
                }
                let package = index
                    .get(&ident)
                    .ok_or_else(|| WitClosureError::MissingPackage {
                        root: root.clone(),
                        missing: ident.clone(),
                        // `Enter` for a non-root always carries its requirer, so
                        // the refusal names both ends of the broken edge.
                        required_by: required_by.clone().unwrap_or_else(|| root.clone()),
                    })?;

                path.push(ident.clone());
                // `Leave` goes on FIRST so every step belonging to this
                // package's subtree is consumed before it — which is what keeps
                // `path` a true ancestor chain.
                stack.push(Step::Leave(ident.clone()));
                // Pushed in reverse so the smallest key is popped first; the
                // emitted order then depends only on the keys.
                for dep in package.imports().iter().rev() {
                    stack.push(Step::Enter {
                        ident: dep.clone(),
                        required_by: Some(ident.clone()),
                    });
                }
            }
            Step::Leave(ident) => {
                path.pop();
                finished.insert(ident.clone());
                order.push(ident);
            }
        }
    }

    Ok(order)
}

/// Why a closure could not be produced. Every variant names the thing that is
/// wrong, because the caller's next move is to fix that thing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitClosureError {
    #[error(
        "these bytes are not a binary WIT package: they decode as a WebAssembly \
         component. A `wit` payload is one encoded WIT package (DD-036)"
    )]
    NotAWitPackage,

    #[error("these bytes are not a readable WebAssembly artifact: {detail}")]
    Undecodable { detail: String },

    #[error(
        "the WIT package '{ident}' declares no version: a layer keys packages by \
         `namespace:name@version`, so an unversioned package has no slot to \
         occupy and no way to be pinned"
    )]
    Unversioned { ident: String },

    #[error("'{text}' is not a WIT package reference; expected `namespace:name@version`")]
    MalformedRef { text: String },

    #[error("the layer does not carry the WIT package {root}")]
    RootMissing { root: PackageIdent },

    #[error(
        "the dependency closure of {root} cannot be completed: the layer does not \
         carry {missing}, which {required_by} imports. No tree is produced — a \
         partial one would fail later inside another tool (REQ-WIT-001 clause 4)"
    )]
    MissingPackage {
        root: PackageIdent,
        missing: PackageIdent,
        required_by: PackageIdent,
    },

    #[error(
        "these WIT packages depend on each other in a cycle, which has no \
         dependency order: {}",
        .path.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" -> ")
    )]
    Cycle { path: Vec<PackageIdent> },

    #[error(
        "two different payloads both claim to be {ident}: sha256:{first} and \
         sha256:{second}. One name must mean one set of bytes (REQ-STORE-002)"
    )]
    ConflictingIdentity {
        ident: PackageIdent,
        first: String,
        second: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Encode a binary WIT package the way the ecosystem does, so the tests
    /// read the same form `wkg` writes (DD-036) rather than a fixture we made
    /// up. `wit-component` is the reference encoder and a dev-dependency only;
    /// nothing in the production path encodes.
    fn encode(files: &[(&str, &str)], top: &str) -> Vec<u8> {
        let mut resolve = wit_parser::Resolve::new();
        let mut top_id = None;
        for (name, source) in files {
            let id = resolve.push_str(name, source).expect("fixture must parse");
            if resolve.packages[id].name.to_string() == top {
                top_id = Some(id);
            }
        }
        wit_component::encode(
            &resolve,
            top_id.expect("fixture must define the top package"),
        )
        .expect("fixture must encode")
    }

    const BASE: &str = "package acme:base@2.0.0;\ninterface b { type t = u32; }\n";
    const LEFT: &str =
        "package acme:left@1.0.0;\ninterface i { use acme:base/b@2.0.0.{t}; type l = t; }\n";
    const RIGHT: &str =
        "package acme:right@1.0.0;\ninterface i { use acme:base/b@2.0.0.{t}; type r = t; }\n";
    const TOP: &str = "package acme:top@0.1.0;\ninterface i { use acme:left/i@1.0.0.{l}; \
                       use acme:right/i@1.0.0.{r}; type a = l; type c = r; }\n\
                       world w { import i; }\n";

    fn ident(s: &str) -> PackageIdent {
        PackageIdent::from_str(s).expect("test reference must parse")
    }

    /// The diamond, as four separately-encoded payloads — which is how a layer
    /// carries them (clause 1), not as one vendored tree.
    fn diamond_index() -> PackageIndex {
        let mut index = PackageIndex::new();
        for bytes in [
            encode(&[("base.wit", BASE)], "acme:base@2.0.0"),
            encode(&[("base.wit", BASE), ("l.wit", LEFT)], "acme:left@1.0.0"),
            encode(&[("base.wit", BASE), ("r.wit", RIGHT)], "acme:right@1.0.0"),
            encode(
                &[
                    ("base.wit", BASE),
                    ("l.wit", LEFT),
                    ("r.wit", RIGHT),
                    ("top.wit", TOP),
                ],
                "acme:top@0.1.0",
            ),
        ] {
            index.insert_binary(&bytes).expect("fixture must index");
        }
        index
    }

    /// Fails if `from_binary` ever takes identity from anything but the decoded
    /// package name — a file name, a caller-supplied label, a manifest field.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn identity_and_imports_come_from_the_packages_own_bytes() {
        let bytes = encode(&[("base.wit", BASE), ("l.wit", LEFT)], "acme:left@1.0.0");
        let package = WitPackage::from_binary(&bytes).unwrap();
        assert_eq!(package.ident(), &ident("acme:left@1.0.0"));
        assert_eq!(package.ident().namespace(), "acme");
        assert_eq!(package.ident().name(), "left");
        assert_eq!(package.ident().version(), "1.0.0");
        // Clause 2: the dependency is read out of the signed bytes. Nothing was
        // handed to `from_binary` but the bytes.
        assert_eq!(
            package.imports().iter().collect::<Vec<_>>(),
            vec![&ident("acme:base@2.0.0")]
        );

        // A SECOND namespace, and a dependency across it. Without this, every
        // fixture in the module lives in `acme`, and a `from_binary` that
        // hard-coded the namespace would pass the assertions above — which is
        // not a hypothetical: the negative control that hard-coded "acme"
        // survived this test until these lines were added.
        let dep = "package otherns:thing@3.1.4;\ninterface i { type t = u32; }\n";
        let user = "package acme:user@0.0.1;\n\
                    interface i { use otherns:thing/i@3.1.4.{t}; type u = t; }\n";
        let package =
            WitPackage::from_binary(&encode(&[("d.wit", dep)], "otherns:thing@3.1.4")).unwrap();
        assert_eq!(package.ident().namespace(), "otherns");
        assert_eq!(package.ident().name(), "thing");
        assert_eq!(package.ident().version(), "3.1.4");

        let package = WitPackage::from_binary(&encode(
            &[("d.wit", dep), ("u.wit", user)],
            "acme:user@0.0.1",
        ))
        .unwrap();
        assert_eq!(
            package.imports().iter().collect::<Vec<_>>(),
            vec![&ident("otherns:thing@3.1.4")]
        );
    }

    /// Fails if the walk stops deduplicating — the encoding names a foreign
    /// package once per reference, so a dependency reached twice would be
    /// emitted twice and `deps/` would be written twice.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_diamond_visits_the_shared_base_exactly_once() {
        let index = diamond_index();
        let order = closure(&index, &ident("acme:top@0.1.0")).unwrap();
        assert_eq!(
            order
                .iter()
                .filter(|p| **p == ident("acme:base@2.0.0"))
                .count(),
            1,
            "a diamond is a DAG, not a repetition: {order:?}"
        );
        assert_eq!(order.len(), 4, "{order:?}");
        // Deps precede dependents, and the root is last.
        let at = |s: &str| order.iter().position(|p| *p == ident(s)).unwrap();
        assert!(at("acme:base@2.0.0") < at("acme:left@1.0.0"));
        assert!(at("acme:base@2.0.0") < at("acme:right@1.0.0"));
        assert!(at("acme:left@1.0.0") < at("acme:top@0.1.0"));
        assert!(at("acme:right@1.0.0") < at("acme:top@0.1.0"));
        assert_eq!(order.last().unwrap(), &ident("acme:top@0.1.0"));
    }

    /// Fails if `closure` drops the `on_path` set and decides visitation with
    /// one "seen" set — which turns this into an infinite loop or a silent
    /// truncation instead of a refusal.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_cycle_is_refused_and_the_cycle_is_named() {
        // Two payloads that each name the other. A single `Resolve` cannot
        // express this, which is the point: the cycle only becomes
        // representable once packages are stored SEPARATELY, so it is a state
        // a layer can really be in.
        let a_stub = "package acme:a@1.0.0;\ninterface x { type ta = u32; }\n";
        let b_stub = "package acme:b@1.0.0;\ninterface y { type tb = u64; }\n";
        let a = "package acme:a@1.0.0;\ninterface x { use acme:b/y@1.0.0.{tb}; type ta = tb; }\n\
                 world w { import x; }\n";
        let b = "package acme:b@1.0.0;\ninterface y { use acme:a/x@1.0.0.{ta}; type tb = ta; }\n\
                 world w { import y; }\n";

        let mut index = PackageIndex::new();
        index
            .insert_binary(&encode(&[("b.wit", b_stub), ("a.wit", a)], "acme:a@1.0.0"))
            .unwrap();
        index
            .insert_binary(&encode(&[("a.wit", a_stub), ("b.wit", b)], "acme:b@1.0.0"))
            .unwrap();

        let err = closure(&index, &ident("acme:a@1.0.0")).unwrap_err();
        match &err {
            WitClosureError::Cycle { path } => {
                // The report has to be traversable: first and last are the same
                // package, or it does not describe a cycle.
                assert_eq!(path.first(), path.last(), "{path:?}");
                assert_eq!(path.len(), 3, "{path:?}");
                assert!(path.contains(&ident("acme:b@1.0.0")), "{path:?}");
            }
            other => panic!("expected a cycle, got {other:?}"),
        }
        assert!(
            err.to_string().contains("acme:a@1.0.0 -> acme:b@1.0.0"),
            "the message must show the cycle: {err}"
        );
    }

    /// Fails if a missing dependency is ever skipped, warned about, or returned
    /// alongside a shortened list. Clause 4: the refusal IS the product.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_missing_dependency_is_a_refusal_naming_it_not_a_partial_tree() {
        let mut index = PackageIndex::new();
        // `left` is carried; the `base` it imports is not.
        index
            .insert_binary(&encode(
                &[("base.wit", BASE), ("l.wit", LEFT)],
                "acme:left@1.0.0",
            ))
            .unwrap();

        let err = closure(&index, &ident("acme:left@1.0.0")).unwrap_err();
        assert_eq!(
            err,
            WitClosureError::MissingPackage {
                root: ident("acme:left@1.0.0"),
                missing: ident("acme:base@2.0.0"),
                required_by: ident("acme:left@1.0.0"),
            }
        );
        // Both ends of the broken edge appear, because "something is missing"
        // is not actionable and "base is missing, left wants it" is.
        let text = err.to_string();
        assert!(text.contains("acme:base@2.0.0"), "{text}");
        assert!(text.contains("acme:left@1.0.0"), "{text}");
    }

    /// Fails if the root-missing case is folded into `MissingPackage` — the two
    /// have different fixes, and a report that the layer lacks a dependency of
    /// a package it does not carry at all sends the reader the wrong way.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_root_the_layer_does_not_carry_is_its_own_refusal() {
        let index = diamond_index();
        let err = closure(&index, &ident("acme:absent@9.9.9")).unwrap_err();
        assert_eq!(
            err,
            WitClosureError::RootMissing {
                root: ident("acme:absent@9.9.9")
            }
        );
    }

    /// Fails if any part of the walk starts reading a `HashSet`, a `HashMap`,
    /// or insertion order. The closure feeds a signed artifact: two machines
    /// that order it differently sign different things.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn the_order_depends_only_on_the_keys() {
        let forwards = diamond_index();
        let mut backwards = PackageIndex::new();
        // The same four payloads, inserted in the opposite order.
        let mut payloads = vec![
            encode(&[("base.wit", BASE)], "acme:base@2.0.0"),
            encode(&[("base.wit", BASE), ("l.wit", LEFT)], "acme:left@1.0.0"),
            encode(&[("base.wit", BASE), ("r.wit", RIGHT)], "acme:right@1.0.0"),
            encode(
                &[
                    ("base.wit", BASE),
                    ("l.wit", LEFT),
                    ("r.wit", RIGHT),
                    ("top.wit", TOP),
                ],
                "acme:top@0.1.0",
            ),
        ];
        payloads.reverse();
        for bytes in &payloads {
            backwards.insert_binary(bytes).unwrap();
        }

        let root = ident("acme:top@0.1.0");
        let a = closure(&forwards, &root).unwrap();
        let b = closure(&backwards, &root).unwrap();
        assert_eq!(a, b, "insertion order must not reach the result");
        // And the same index answers the same way twice.
        assert_eq!(a, closure(&forwards, &root).unwrap());
        // Pinned exactly, so a change to the tie-breaking rule is visible here
        // rather than only on some other machine.
        assert_eq!(
            a.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            vec![
                "acme:base@2.0.0",
                "acme:left@1.0.0",
                "acme:right@1.0.0",
                "acme:top@0.1.0",
            ]
        );
    }

    /// Fails if `insert` starts overwriting, or starts refusing, on digest
    /// equality — the two halves of "one name, one set of bytes".
    // rivet: verifies REQ-WIT-001, REQ-STORE-002
    #[test]
    fn one_name_may_not_mean_two_sets_of_bytes() {
        let base = encode(&[("base.wit", BASE)], "acme:base@2.0.0");
        // Same name and version, different contents. Both would sign fine.
        let impostor = encode(
            &[(
                "base.wit",
                "package acme:base@2.0.0;\ninterface b { type t = u64; }\n",
            )],
            "acme:base@2.0.0",
        );
        assert_ne!(base, impostor, "the fixture must actually differ");

        let mut index = PackageIndex::new();
        index.insert_binary(&base).unwrap();
        // The same payload offered again is not a conflict: a layer may reach
        // one package by more than one route.
        index.insert_binary(&base).unwrap();
        assert_eq!(index.len(), 1);

        let err = index.insert_binary(&impostor).unwrap_err();
        match err {
            WitClosureError::ConflictingIdentity {
                ident: id,
                first,
                second,
            } => {
                assert_eq!(id, ident("acme:base@2.0.0"));
                assert_ne!(first, second);
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        // The first entry stands; a refusal that had already overwritten would
        // be a refusal in name only.
        assert_eq!(
            index.get(&ident("acme:base@2.0.0")).unwrap().digest(),
            &hex::encode(Sha256::digest(&base))
        );
    }

    /// Fails if `PackageIdent` is ever re-keyed on a parsed `semver::Version`,
    /// whose ordering treats build metadata as absent — collapsing two distinct
    /// payloads into one key.
    // rivet: verifies REQ-WIT-001, REQ-STORE-002
    #[test]
    fn build_metadata_is_part_of_the_identity() {
        let one = encode(
            &[(
                "m.wit",
                "package acme:m@1.0.0+build.one;\ninterface i { type t = u32; }\n",
            )],
            "acme:m@1.0.0+build.one",
        );
        let two = encode(
            &[(
                "m.wit",
                "package acme:m@1.0.0+build.two;\ninterface i { type t = u64; }\n",
            )],
            "acme:m@1.0.0+build.two",
        );
        let mut index = PackageIndex::new();
        index.insert_binary(&one).unwrap();
        index.insert_binary(&two).unwrap();
        assert_eq!(
            index.len(),
            2,
            "two payloads, two slots: {:?}",
            index.idents().collect::<Vec<_>>()
        );
        assert_ne!(
            ident("acme:m@1.0.0+build.one"),
            ident("acme:m@1.0.0+build.two")
        );
        // And they land in different places in the store.
        assert_ne!(
            ident("acme:m@1.0.0+build.one").binary_path(),
            ident("acme:m@1.0.0+build.two").binary_path()
        );
    }

    /// Fails if `from_binary` starts accepting whatever decodes — a core module
    /// and a finished component both decode cleanly and are not WIT packages.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn only_a_wit_package_is_a_wit_payload() {
        // An empty core module: valid WebAssembly, no WIT in it.
        let core = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            WitPackage::from_binary(&core).unwrap_err(),
            WitClosureError::NotAWitPackage
        );

        // Not WebAssembly at all: a typed refusal, not a panic.
        let err = WitPackage::from_binary(b"this is not wasm").unwrap_err();
        assert!(
            matches!(err, WitClosureError::Undecodable { .. }),
            "{err:?}"
        );
        // The detail has to survive, or the depositor has nothing to look at.
        assert!(err.to_string().contains("magic"), "{err}");
    }

    /// Fails if the version stops being required. A flat store keyed
    /// `namespace:name@version` has no slot for a package without one, and
    /// inventing "latest" or "0.0.0" would invent an identity.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn an_unversioned_package_has_no_slot_and_is_refused() {
        let bytes = encode(
            &[(
                "u.wit",
                "package acme:unversioned;\ninterface i { type t = u32; }\n",
            )],
            "acme:unversioned",
        );
        let err = WitPackage::from_binary(&bytes).unwrap_err();
        assert_eq!(
            err,
            WitClosureError::Unversioned {
                ident: "acme:unversioned".to_string()
            }
        );
    }

    /// Fails if `PackageIdent::new` drops its character check — the three fields
    /// are joined into a store path, so `..` reaching it is a traversal.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_reference_round_trips_and_cannot_smuggle_a_path() {
        let id = ident("wasi:io@0.2.0");
        assert_eq!(id.to_string(), "wasi:io@0.2.0");
        assert_eq!(id.binary_path(), "wasi/io/0.2.0.wasm");
        assert_eq!(
            ident("wasi:io@0.2.0-rc.1").binary_path(),
            "wasi/io/0.2.0-rc.1.wasm"
        );

        for bad in [
            "wasi:io",             // no version
            "wasi/io@0.2.0",       // no namespace separator
            ":io@0.2.0",           // empty namespace
            "wasi:@0.2.0",         // empty name
            "wasi:io@",            // empty version
            "..:io@0.2.0",         // traversal in the namespace
            "wasi:..@0.2.0",       // traversal in the name
            "wasi:io@..",          // traversal in the version
            "wasi:io@../../etc",   // traversal via a separator
            "wasi:i/o@0.2.0",      // separator inside the name
            "wasi:io@0.2.0:extra", // a second `:` is not absorbed
        ] {
            let err = PackageIdent::from_str(bad).unwrap_err();
            assert!(
                matches!(err, WitClosureError::MalformedRef { .. }),
                "{bad} should be refused, got {err:?}"
            );
        }
    }

    /// Fails if a leaf package's closure stops including the leaf itself — a
    /// consumer asking for `base` must still be told to lay `base` down.
    /// The index's own accessors report what it holds.
    ///
    /// Added because the mutation shard this module was gated into on arrival
    /// reported four survivors here and nowhere else: `as_str`, `is_empty`
    /// (both directions) and `idents` were reachable only through other
    /// assertions, so replacing each with a constant changed nothing any test
    /// looked at. They are small, and that is the point — `idents` returning
    /// nothing is how an export would compose an empty tree and call it a
    /// closure.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn the_index_reports_what_it_actually_holds() {
        let empty = PackageIndex::new();
        assert!(empty.is_empty(), "a fresh index is empty");
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.idents().count(), 0);

        // The diamond fixture carries four packages across two namespaces.
        let idx = diamond_index();
        assert!(!idx.is_empty(), "an index holding packages is not empty");
        assert_eq!(idx.len(), 4);

        // …and `idents` yields exactly those, in key order — an empty
        // iterator or a different set is a different layer.
        let got: Vec<String> = idx.idents().map(|i| i.as_str().to_string()).collect();
        assert_eq!(got.len(), 4, "got {got:?}");
        assert!(got.contains(&"acme:base@2.0.0".to_string()), "{got:?}");
        let mut sorted = got.clone();
        sorted.sort();
        assert_eq!(got, sorted, "idents must yield key order: {got:?}");

        // `as_str` is the key as written, not a rendering of the parts.
        let ident: PackageIdent = "acme:base@2.0.0".parse().unwrap();
        assert_eq!(ident.as_str(), "acme:base@2.0.0");
    }

    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_package_with_no_dependencies_closes_over_itself() {
        let mut index = PackageIndex::new();
        index
            .insert_binary(&encode(&[("base.wit", BASE)], "acme:base@2.0.0"))
            .unwrap();
        assert_eq!(
            closure(&index, &ident("acme:base@2.0.0")).unwrap(),
            vec![ident("acme:base@2.0.0")]
        );
    }
}
