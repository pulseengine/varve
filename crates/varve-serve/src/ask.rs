//! `varve-serve ask`: pointers, not text (REQ-AGENTDOCS-002).
//!
//! The index is built when the question is asked, from material that is
//! already verified, and thrown away. It is never signed and never shipped: a
//! producer-built index would be a claim no consumer can check without
//! recomputing it.
//!
//! What it indexes (each source was measured to matter): documentation pages
//! (title and path), every tool's subcommands, every tool's one-line overview
//! with its warning, the TEXT of the built-in docs topics the tool advertised,
//! `varve`'s own subcommands, held payloads, and the names a tool's warning
//! points at that the pin lacks.
//!
//! What it returns is a hit: an id, a kind, a title, the layer, the payload
//! digest where there is one, and `read` — the exact command that shows the
//! whole page or topic. Never the matched text itself: an answer made of
//! documentation text is documentation text loaded into an agent's context.
//!
//! Scoring is lexical and plain, because the measurement that justified it was
//! on a few hundred short units where the failures were not about semantics:
//!
//! * **Stopwords** — a full-sentence question matched on "the", "is" and
//!   "where". Filtering them was the largest single gain (0/9 to 7/9 in the
//!   top three).
//! * **Exact item** — the rustdoc page whose item IS the query word
//!   (`struct.Store.html` for "Store") outranks the pages merely in a module
//!   of that name.
//! * **Named tool** — a hit about a tool the query names outranks the same
//!   words about another tool.

use serde_json::{Value, json};

use crate::context::{Context, get_command};
use crate::docpages;

/// Words that carry no question. Matching them turns every sentence into noise.
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "do", "does", "did", "how", "what",
    "which", "where", "when", "why", "who", "can", "could", "should", "would", "will", "i", "me",
    "my", "we", "you", "it", "its", "this", "that", "these", "those", "to", "of", "in", "on", "at",
    "by", "for", "from", "with", "and", "or", "not", "no", "as", "if", "so", "there", "here",
    "about", "into", "than", "then", "use", "using", "used", "get", "want", "need", "tell", "show",
    "give", "find", "please", "project", "pinned", "pin", "here's",
];

const NAME: u32 = 3;
const DESC: u32 = 2;
const BODY: u32 = 1;
const PARTIAL: u32 = 1;
const EXACT_ITEM: u32 = 10;
const NAMED_TOOL: u32 = 6;

/// The default number of hits.
pub const DEFAULT_LIMIT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Absent,
    DocsPage,
    Held,
    ToolOverview,
    ToolSubcommand,
    Topic,
    VarveCommand,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Absent => "absent",
            Kind::DocsPage => "docs-page",
            Kind::Held => "held-payload",
            Kind::ToolOverview => "tool-overview",
            Kind::ToolSubcommand => "tool-subcommand",
            Kind::Topic => "topic",
            Kind::VarveCommand => "varve-command",
        }
    }
}

/// One thing that can be pointed at.
#[derive(Debug, Clone)]
pub struct Unit {
    pub kind: Kind,
    pub id: String,
    pub title: String,
    /// The words that NAME it (a path, a subcommand, a tool).
    pub name: String,
    /// A description of it.
    pub desc: String,
    /// Text searched but never shown (a docs topic's body).
    pub body: String,
    /// The tool it is about, if it is about one.
    pub tool: Option<String>,
    /// For a documentation page: the item the page IS, lowercased.
    pub item: Option<String>,
    pub layer: String,
    pub digest: Option<String>,
    pub read: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub score: u32,
    pub layer: String,
    pub digest: Option<String>,
    pub read: String,
}

/// Lowercase alphanumeric runs.
pub fn tokens(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// The content words of a question: stopwords and one-letter words removed,
/// each word once, in the order asked.
pub fn query_words(query: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tokens(query) {
        if t.chars().count() > 1 && !STOPWORDS.contains(&t.as_str()) && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

const RUSTDOC_KINDS: &[&str] = &[
    "struct",
    "enum",
    "trait",
    "fn",
    "type",
    "macro",
    "constant",
    "union",
    "static",
    "attr",
    "derive",
    "primitive",
    "keyword",
    "traitalias",
];

/// The item a documentation page IS: `struct.Store.html` is `store`, and a
/// title `Store in varve_core::store - Rust` is `store`. A module's
/// `index.html` is no item.
pub fn item_of(path: &str, title: &str) -> Option<String> {
    let file = path.rsplit('/').next().unwrap_or(path);
    let parts: Vec<&str> = file.split('.').collect();
    if let [kind, item, "html"] = parts.as_slice()
        && RUSTDOC_KINDS.contains(kind)
    {
        return Some(item.to_lowercase());
    }
    let (head, _) = title.split_once(" in ")?;
    let last = head.split_whitespace().last()?;
    (!last.contains("::")).then(|| last.to_lowercase())
}

fn base_score(u: &Unit, words: &[String]) -> u32 {
    let name = tokens(&u.name);
    let desc = tokens(&format!("{} {}", u.title, u.desc));
    let body = tokens(&u.body);
    let name_lower = u.name.to_lowercase();
    words
        .iter()
        .map(|w| {
            if name.contains(w) {
                NAME
            } else if desc.contains(w) {
                DESC
            } else if body.contains(w) {
                BODY
            } else if w.len() >= 3 && name_lower.contains(w.as_str()) {
                PARTIAL
            } else {
                0
            }
        })
        .sum()
}

fn score(u: &Unit, words: &[String]) -> u32 {
    // A query that names the tool a unit is about: the name itself says
    // nothing about WHICH of that tool's subcommands is meant, so it is taken
    // out of the matching and paid as one flat boost instead. Left in, it
    // would match the title of every one of the tool's units.
    let named = u
        .tool
        .as_ref()
        .is_some_and(|t| words.contains(&t.to_lowercase()));
    let rest: Vec<String> = if named {
        let tool = u.tool.as_deref().unwrap_or_default().to_lowercase();
        words.iter().filter(|w| **w != tool).cloned().collect()
    } else {
        words.to_vec()
    };
    if named && rest.is_empty() {
        // The question is only the tool's name: its overview is the answer.
        return if u.kind == Kind::ToolOverview {
            NAME + NAMED_TOOL
        } else {
            0
        };
    }
    let base = base_score(u, &rest);
    if base == 0 {
        return 0;
    }
    let mut s = base;
    if let Some(item) = &u.item
        && words.contains(item)
    {
        s += EXACT_ITEM;
    }
    if named {
        s += NAMED_TOOL;
    }
    s
}

/// Rank `units` for `query`, best first, ties broken by `(kind, id)`.
pub fn search(units: &[Unit], query: &str, limit: usize) -> Vec<Hit> {
    let words = query_words(query);
    let mut hits: Vec<Hit> = units
        .iter()
        .filter_map(|u| {
            let s = score(u, &words);
            (s > 0).then(|| Hit {
                id: u.id.clone(),
                kind: u.kind,
                title: u.title.clone(),
                score: s,
                layer: u.layer.clone(),
                digest: u.digest.clone(),
                read: u.read.clone(),
            })
        })
        .collect();
    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(a.kind.cmp(&b.kind))
            .then(a.id.cmp(&b.id))
    });
    hits.truncate(limit);
    hits
}

/// Build the index over everything the orientation knows plus the pages of
/// every docs payload.
pub fn index(ctx: &Context) -> anyhow::Result<Vec<Unit>> {
    let layer = ctx.facts.layer.clone();
    let mut units = Vec::new();
    for t in &ctx.tools {
        let tool = Some(t.name.clone());
        let mut about = t
            .summary
            .as_ref()
            .map(|(s, _)| s.clone())
            .unwrap_or_default();
        if let Some(w) = &t.warning {
            about.push(' ');
            about.push_str(w);
        }
        units.push(Unit {
            kind: Kind::ToolOverview,
            id: format!("tool:{}:overview", t.name),
            title: format!("`{}` — {}", t.name, about.trim()),
            name: t.name.clone(),
            desc: about,
            body: String::new(),
            tool: tool.clone(),
            item: None,
            layer: t.layer.clone(),
            digest: Some(t.digest.clone()),
            read: format!("{} --help", t.name),
        });
        for s in &t.subs {
            units.push(Unit {
                kind: Kind::ToolSubcommand,
                id: format!("tool:{}:sub:{}", t.name, s.name),
                title: format!("`{} {}` — {}", t.name, s.name, s.desc),
                name: s.name.clone(),
                desc: s.desc.clone(),
                body: String::new(),
                tool: tool.clone(),
                item: None,
                layer: t.layer.clone(),
                digest: Some(t.digest.clone()),
                read: format!("{} {} --help", t.name, s.name),
            });
        }
        let docs = t
            .docs_command
            .clone()
            .unwrap_or_else(|| format!("{} docs", t.name));
        for topic in &t.topic_texts {
            units.push(Unit {
                kind: Kind::Topic,
                id: format!("topic:{}:{}", t.name, topic.name),
                title: format!("`{docs} {}` — {}", topic.name, topic.desc),
                name: topic.name.clone(),
                desc: topic.desc.clone(),
                body: topic.body.clone(),
                tool: tool.clone(),
                item: None,
                layer: t.layer.clone(),
                digest: Some(t.digest.clone()),
                read: format!("{docs} {}", topic.name),
            });
        }
    }
    for (name, desc) in crate::varvecmds::COMMANDS {
        units.push(Unit {
            kind: Kind::VarveCommand,
            id: format!("varve:{name}"),
            title: format!("`varve {name}` — {desc}"),
            name: name.to_string(),
            desc: desc.to_string(),
            body: String::new(),
            tool: Some("varve".into()),
            item: None,
            layer: layer.clone(),
            digest: None,
            read: format!("varve {name} --help"),
        });
    }
    for h in &ctx.held {
        let get = get_command(h);
        units.push(Unit {
            kind: Kind::Held,
            id: format!("held:{}:{}", h.kind, h.name),
            title: format!(
                "{} `{}` {} — get it out: `{get}`",
                h.kind, h.name, h.version
            ),
            name: format!("{} {}", h.name, h.kind),
            desc: format!("held payload, stored and verified, not on PATH. {get}"),
            body: String::new(),
            tool: None,
            item: None,
            layer: layer.clone(),
            digest: None,
            read: get,
        });
    }
    for a in &ctx.absent {
        units.push(Unit {
            kind: Kind::Absent,
            id: format!("absent:{}", a.name),
            title: format!(
                "`{}` is NOT in this pin — `{}` points at it, but this layer does not carry it",
                a.name, a.named_by
            ),
            name: a.name.clone(),
            desc: format!("not in this pin, named by {}", a.named_by),
            body: String::new(),
            tool: None,
            item: None,
            layer: layer.clone(),
            digest: None,
            read: "varve inspect".into(),
        });
    }
    for d in &ctx.docs {
        let p = &d.payload;
        if !p.format.is_tree() {
            units.push(Unit {
                kind: Kind::DocsPage,
                id: format!("docs:{}", p.name),
                title: p.title.clone().unwrap_or_else(|| p.name.clone()),
                name: p.name.clone(),
                desc: p.documents.clone().unwrap_or_default(),
                body: String::new(),
                tool: None,
                item: None,
                layer: d.layer.clone(),
                digest: Some(d.digest.clone()),
                read: format!("varve export-docs --out ./doc --select {}", p.name),
            });
            continue;
        }
        for page in docpages::pages(p)? {
            units.push(Unit {
                kind: Kind::DocsPage,
                id: format!("docs:{}:{}", p.name, page.path),
                item: item_of(&page.path, &page.title),
                title: page.title.clone(),
                name: page.path.clone(),
                desc: String::new(),
                body: String::new(),
                tool: None,
                layer: d.layer.clone(),
                digest: Some(d.digest.clone()),
                read: format!("varve-serve page {} {}", p.name, page.path),
            });
        }
    }
    Ok(units)
}

pub fn render_md(query: &str, ctx: &Context, hits: &[Hit]) -> String {
    let mut o = format!(
        "# ask: \"{query}\" (layer {}, realm {})\n\n",
        ctx.facts.layer, ctx.facts.realm
    );
    if hits.is_empty() {
        o.push_str(&format!(
            "no hits for \"{query}\". `varve inspect` lists everything the pin holds.\n"
        ));
        return o;
    }
    for (i, h) in hits.iter().enumerate() {
        o.push_str(&format!(
            "{}. [{}] {} (score {})\n   id: {}\n   layer: {}",
            i + 1,
            h.kind.as_str(),
            h.title,
            h.score,
            h.id,
            h.layer
        ));
        if let Some(d) = &h.digest {
            o.push_str(&format!("  digest: {d}"));
        }
        o.push_str(&format!("\n   read: `{}`\n", h.read));
    }
    o
}

pub fn render_json(query: &str, ctx: &Context, hits: &[Hit]) -> String {
    let doc = json!({
        "query": query,
        "layer": ctx.facts.layer,
        "realm": ctx.facts.realm,
        "hits": hits.iter().map(|h| json!({
            "id": h.id,
            "kind": h.kind.as_str(),
            "title": h.title,
            "score": h.score,
            "layer": h.layer,
            "digest": h.digest,
            "read": h.read,
        })).collect::<Vec<Value>>(),
    });
    let mut s = serde_json::to_string_pretty(&doc).expect("a json value serialises");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(kind: Kind, id: &str, name: &str, title: &str, desc: &str) -> Unit {
        Unit {
            kind,
            id: id.into(),
            title: title.into(),
            name: name.into(),
            desc: desc.into(),
            body: String::new(),
            tool: None,
            item: None,
            layer: "L".into(),
            digest: None,
            read: format!("read {id}"),
        }
    }

    fn ids(h: &[Hit]) -> Vec<&str> {
        h.iter().map(|h| h.id.as_str()).collect()
    }

    /// Filler words are removed, once-each, in order; one-letter tokens go.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn stopwords_are_filtered_from_a_question() {
        assert_eq!(
            query_words("Where is the Store type defined, and how do I use the Store?"),
            ["store", "type", "defined"]
        );
        assert_eq!(query_words("a I x"), Vec::<String>::new());
        assert_eq!(
            query_words("rivet add-requirement"),
            ["rivet", "add", "requirement"]
        );
        assert_eq!(
            tokens("varve_core::Store.html"),
            ["varve", "core", "store", "html"]
        );
    }

    /// With the filter a sentence ranks like its content words; without it, a
    /// unit named after a filler word would lead.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_full_sentence_ranks_like_its_content_words() {
        let units = vec![
            unit(
                Kind::ToolSubcommand,
                "tool:p:sub:where",
                "where",
                "`p where`",
                "Tell where the type lives",
            ),
            unit(
                Kind::DocsPage,
                "docs:d:struct.Store.html",
                "d/struct.Store.html",
                "Store in d - Rust",
                "",
            ),
        ];
        let short = search(&units, "Store type", 5);
        let long = search(&units, "where is the Store type", 5);
        assert_eq!(ids(&long), ids(&short));
        assert_eq!(long[0].score, short[0].score);
        assert_eq!(long[0].id, "docs:d:struct.Store.html");
        assert!(
            search(&units, "the of and", 5).is_empty(),
            "only filler matches nothing"
        );
    }

    /// The page that IS the item beats the module page and the function page.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn the_item_page_outranks_pages_in_a_module_of_that_name() {
        let mut item = unit(
            Kind::DocsPage,
            "d:struct",
            "v/store/struct.Store.html",
            "Store in v::store - Rust",
            "",
        );
        item.item = item_of("v/store/struct.Store.html", "Store in v::store - Rust");
        let mut module = unit(
            Kind::DocsPage,
            "d:module",
            "v/store/index.html",
            "v::store - Rust",
            "",
        );
        module.item = item_of("v/store/index.html", "v::store - Rust");
        let mut func = unit(
            Kind::DocsPage,
            "d:fn",
            "v/store/fn.open_store.html",
            "open_store in v::store - Rust",
            "",
        );
        func.item = item_of(
            "v/store/fn.open_store.html",
            "open_store in v::store - Rust",
        );
        let hits = search(&[module, func, item], "Store", 5);
        assert_eq!(
            ids(&hits),
            ["d:struct", "d:fn", "d:module"].map(String::from)
        );
        assert_eq!(hits[0].score, NAME + EXACT_ITEM, "{hits:?}");
        assert_eq!(hits[1].score, NAME, "{hits:?}");
    }

    #[test]
    fn an_item_is_found_from_the_path_or_the_title() {
        assert_eq!(
            item_of("a/b/struct.Store.html", "x").as_deref(),
            Some("store")
        );
        assert_eq!(item_of("a/trait.Foo.html", "x").as_deref(), Some("foo"));
        assert_eq!(item_of("a/index.html", "a::b - Rust"), None);
        assert_eq!(
            item_of("a/page.html", "Store in a::b - Rust").as_deref(),
            Some("store")
        );
        assert_eq!(item_of("a/page.html", "a::b in c - Rust"), None);
        assert_eq!(
            item_of("a/mod.Foo.html", "x"),
            None,
            "`mod` is not an item kind"
        );
        assert_eq!(item_of("a/struct.Foo.txt", "x"), None);
    }

    /// A hit about the tool the query names outranks the same words elsewhere,
    /// but only where something else matched.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_hit_about_the_named_tool_outranks_others() {
        let mut a = unit(
            Kind::ToolSubcommand,
            "tool:rivet:sub:add",
            "add",
            "`rivet add`",
            "Add an artifact",
        );
        a.tool = Some("rivet".into());
        let mut b = unit(
            Kind::ToolSubcommand,
            "tool:other:sub:add",
            "add",
            "`other add`",
            "Add an artifact",
        );
        b.tool = Some("other".into());
        let mut unrelated = unit(
            Kind::ToolSubcommand,
            "tool:rivet:sub:zzz",
            "zzz",
            "`rivet zzz`",
            "Nothing",
        );
        unrelated.tool = Some("rivet".into());
        let mut overview = unit(
            Kind::ToolOverview,
            "tool:rivet:overview",
            "rivet",
            "`rivet` — traceability",
            "traceability",
        );
        overview.tool = Some("rivet".into());
        let only = search(
            &[b.clone(), a.clone(), unrelated.clone(), overview],
            "rivet",
            5,
        );
        assert_eq!(
            ids(&only),
            ["tool:rivet:overview"].map(String::from),
            "only the overview answers a bare tool name"
        );
        assert_eq!(only[0].score, NAME + NAMED_TOOL);
        let hits = search(&[b.clone(), a.clone(), unrelated], "rivet add", 5);
        assert_eq!(
            ids(&hits),
            ["tool:rivet:sub:add", "tool:other:sub:add"].map(String::from)
        );
        assert_eq!(hits[0].score, hits[1].score + NAMED_TOOL);
        // not named: equal scores, so the id decides
        let hits = search(&[b, a], "add", 5);
        assert_eq!(
            ids(&hits),
            ["tool:other:sub:add", "tool:rivet:sub:add"].map(String::from)
        );
    }

    /// Name beats description beats body; a partial name match is weakest; and
    /// a body-only hit still counts, so topic text is searchable.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn weights_order_name_over_description_over_body() {
        let name = unit(Kind::Topic, "n", "zebra", "t", "");
        let desc = unit(Kind::Topic, "d", "other", "t", "a zebra here");
        let mut body = unit(Kind::Topic, "b", "other2", "t", "");
        body.body = "text about a zebra".into();
        let part = unit(Kind::Topic, "p", "zebras", "t", "");
        let w = vec!["zebra".to_string()];
        assert_eq!(score(&name, &w), NAME);
        assert_eq!(score(&desc, &w), DESC);
        assert_eq!(score(&body, &w), BODY);
        assert_eq!(score(&part, &w), PARTIAL);
        assert_eq!(
            score(
                &unit(Kind::Topic, "x", "zeb", "t", ""),
                &["zeb".to_string()]
            ),
            NAME
        );
        // a two-letter word does not match by substring
        assert_eq!(
            score(
                &unit(Kind::Topic, "y", "rivet", "t", ""),
                &["iv".to_string()]
            ),
            0
        );
        let hits = search(&[part, body, desc, name], "zebra", 5);
        assert_eq!(ids(&hits), ["n", "d", "b", "p"].map(String::from));
    }

    /// Equal scores are ordered by kind, then id; the limit cuts after
    /// sorting; two runs agree.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn ties_break_by_kind_then_id_and_the_limit_cuts_after_sorting() {
        let units = vec![
            unit(Kind::Topic, "t:b", "x", "t", ""),
            unit(Kind::DocsPage, "d:b", "x", "t", ""),
            unit(Kind::DocsPage, "d:a", "x", "t", ""),
            unit(Kind::Absent, "a:z", "x", "t", ""),
        ];
        let all = search(&units, "x1 xx x", 10);
        assert!(all.is_empty(), "one-letter and absent words match nothing");
        let units: Vec<Unit> = units
            .into_iter()
            .map(|mut u| {
                u.name = "word".into();
                u
            })
            .collect();
        let all = search(&units, "word", 10);
        assert_eq!(ids(&all), ["a:z", "d:a", "d:b", "t:b"].map(String::from));
        assert_eq!(
            ids(&search(&units, "word", 2)),
            ["a:z", "d:a"].map(String::from)
        );
        assert_eq!(search(&units, "word", 10), all);
        assert!(search(&units, "word", 0).is_empty());
    }

    #[test]
    fn kinds_have_stable_names() {
        let names: Vec<&str> = [
            Kind::Absent,
            Kind::DocsPage,
            Kind::Held,
            Kind::ToolOverview,
            Kind::ToolSubcommand,
            Kind::Topic,
            Kind::VarveCommand,
        ]
        .iter()
        .map(|k| k.as_str())
        .collect();
        assert_eq!(
            names,
            [
                "absent",
                "docs-page",
                "held-payload",
                "tool-overview",
                "tool-subcommand",
                "topic",
                "varve-command"
            ]
        );
    }

    fn ctx_with(tools: Vec<crate::context::ToolInput>) -> Context {
        crate::context::build(
            crate::layers::Facts {
                realm: "r".into(),
                layer: "2026.10.1".into(),
                channel: "rolling".into(),
                manifest_digest: "sha256:aa".into(),
            },
            tools,
            vec![crate::layers::Held {
                kind: "vsix".into(),
                name: "rivet-sdlc".into(),
                version: "0.41.1".into(),
                platforms: vec!["any".into()],
            }],
            vec![],
        )
    }

    fn tool_input(name: &str, help: &str, topics: &[(&str, &str)]) -> crate::context::ToolInput {
        use crate::harvest::{Harvested, Signed, ToolSource, Topic};
        crate::context::ToolInput {
            src: ToolSource {
                name: name.into(),
                version: "1".into(),
                realm: "r".into(),
                layer: "2026.10.1".into(),
                layer_digest: "sha256:aa".into(),
                digest: format!("sha256:{name}"),
                path: None,
                cache_file: None,
            },
            harvested: Harvested {
                help: Some(help.into()),
                topics: topics
                    .iter()
                    .map(|(n, b)| Topic {
                        name: n.to_string(),
                        desc: format!("about {n}"),
                        body: b.to_string(),
                    })
                    .collect(),
            },
            signed: Signed::default(),
        }
    }

    /// Every source of the index yields hits with the exact command that reads
    /// it, the signed digest where there is one, and no matched text.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn the_index_covers_tools_topics_varve_held_and_absent() {
        let kilnd = "Runtime\n\nCommands:\n  run  Run a module\n\nwarning: `kilnd` is deprecated; use `kiln` instead\n";
        let meld = "Fusion\n\nCommands:\n  fuse  Fuse components\n  docs  Docs\n";
        let ctx = ctx_with(vec![
            tool_input("kilnd", kilnd, &[]),
            tool_input("meld", meld, &[("fusion", "the secret zebra paragraph")]),
        ]);
        let units = index(&ctx).unwrap();
        let by_id = |id: &str| {
            units
                .iter()
                .find(|u| u.id == id)
                .unwrap_or_else(|| panic!("no unit {id}"))
        };
        assert_eq!(by_id("tool:meld:sub:fuse").read, "meld fuse --help");
        assert_eq!(by_id("tool:meld:overview").read, "meld --help");
        assert_eq!(
            by_id("tool:meld:sub:fuse").digest.as_deref(),
            Some("sha256:meld")
        );
        assert_eq!(by_id("topic:meld:fusion").read, "meld docs fusion");
        assert!(by_id("topic:meld:fusion").body.contains("zebra"));
        assert_eq!(by_id("varve:export-vsix").read, "varve export-vsix --help");
        assert_eq!(
            by_id("held:vsix:rivet-sdlc").read,
            "varve export-vsix --out ./vsix"
        );
        assert_eq!(by_id("absent:kiln").read, "varve inspect");
        assert!(by_id("tool:kilnd:overview").desc.contains("deprecated"));

        let hits = search(&units, "kiln", 3);
        assert_eq!(hits[0].id, "absent:kiln", "{hits:?}");
        let hits = search(&units, "zebra", 3);
        assert_eq!(hits[0].id, "topic:meld:fusion");
        let json = render_json("zebra", &ctx, &hits);
        assert!(
            !json.contains("secret zebra paragraph"),
            "the matched text leaked: {json}"
        );
        let md = render_md("zebra", &ctx, &hits);
        assert!(!md.contains("secret zebra paragraph"), "{md}");
        let hits = search(&units, "export vsix", 3);
        assert_eq!(hits[0].id, "varve:export-vsix", "{hits:?}");
    }

    /// A single-file document is one unit, read by exporting it; a tree is one
    /// unit per page.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_single_file_document_is_one_unit_and_a_tree_is_many() {
        use crate::layers::DocsSource;
        let src = |name: &str, format, bytes| DocsSource {
            payload: varve_core::docsexport::DocsPayload {
                name: name.into(),
                version: "1".into(),
                format,
                entry: None,
                title: Some(format!("{name} handbook")),
                documents: Some("rivet".into()),
                bytes,
            },
            digest: format!("sha256:{name}"),
            layer: "2026.10.1".into(),
            realm: "r".into(),
        };
        let mut ctx = ctx_with(vec![]);
        ctx.docs = vec![
            src(
                "manual",
                varve_core::layerspec::DocsFormat::Pdf,
                vec![1, 2, 3],
            ),
            src(
                "site",
                varve_core::layerspec::DocsFormat::Html,
                crate::fixture::tar_gz(&[("a.html", "<title>Alpha</title>"), ("b.md", "# Beta")]),
            ),
        ];
        let units = index(&ctx).unwrap();
        let docs: Vec<&Unit> = units.iter().filter(|u| u.kind == Kind::DocsPage).collect();
        let by = |id: &str| {
            docs.iter()
                .find(|u| u.id == id)
                .unwrap_or_else(|| panic!("{id}"))
        };
        assert_eq!(docs.len(), 3);
        assert_eq!(
            by("docs:manual").read,
            "varve export-docs --out ./doc --select manual"
        );
        assert_eq!(by("docs:manual").digest.as_deref(), Some("sha256:manual"));
        assert_eq!(by("docs:manual").title, "manual handbook");
        assert_eq!(by("docs:manual").desc, "rivet");
        assert_eq!(by("docs:site:a.html").read, "varve-serve page site a.html");
        assert_eq!(by("docs:site:a.html").title, "Alpha");
        assert_eq!(by("docs:site:b.md").title, "Beta");
    }

    /// The Markdown and JSON forms carry the same hit, and say plainly when
    /// there is none.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn rendering_names_the_hit_its_digest_and_the_empty_answer() {
        let ctx = ctx_with(vec![tool_input(
            "meld",
            "Fusion\n\nCommands:\n  fuse  Fuse\n",
            &[],
        )]);
        let units = index(&ctx).unwrap();
        let hits = search(&units, "meld fuse", 1);
        let md = render_md("meld fuse", &ctx, &hits);
        assert!(
            md.starts_with("# ask: \"meld fuse\" (layer 2026.10.1, realm r)\n"),
            "{md}"
        );
        assert!(
            md.contains("1. [tool-subcommand] `meld fuse` — Fuse (score "),
            "{md}"
        );
        assert!(md.contains("id: tool:meld:sub:fuse\n"), "{md}");
        assert!(
            md.contains("layer: 2026.10.1  digest: sha256:meld\n"),
            "{md}"
        );
        assert!(md.contains("read: `meld fuse --help`\n"), "{md}");
        let v: Value = serde_json::from_str(&render_json("meld fuse", &ctx, &hits)).unwrap();
        assert_eq!(v["hits"][0]["id"], "tool:meld:sub:fuse");
        assert_eq!(v["hits"][0]["digest"], "sha256:meld");
        assert_eq!(v["hits"][0]["read"], "meld fuse --help");
        assert_eq!(v["hits"][0]["kind"], "tool-subcommand");
        assert_eq!(v["query"], "meld fuse");
        let none = render_md("qqq", &ctx, &[]);
        assert!(
            none.contains("no hits for \"qqq\"") && none.contains("`varve inspect`"),
            "{none}"
        );
        // a hit without a digest says none
        let held = search(&units, "rivet sdlc", 1);
        assert!(!render_md("x", &ctx, &held).contains("digest"));
    }
}
