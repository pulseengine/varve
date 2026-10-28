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

use crate::context::{Context, get_command, shell_word};
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
const SNIPPET_MAX: usize = 160;
const SUBCOMMAND_NAMED: u32 = 3;

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
    /// The best-matching line of a topic: used for ranking, and deliberately
    /// NOT printed — a hit is a pointer, and docs text is a prompt-injection
    /// surface (tests/agent_context.rs plants one).
    pub snippet: Option<String>,
    /// The question's words that the topic's best line holds together.
    pub matched: Vec<String>,
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

/// The rustdoc kinds whose page IS the answer to the item's name.
const TYPE_KINDS: &[&str] = &["struct", "enum", "trait", "type", "union"];

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
        // Only a TYPE page is "the" answer to a word: `fn.sign.html` took the
        // top slot for "sign wasm module" ahead of `wsc sign`, the tool the
        // question was about. A function page still matches by its words.
        return TYPE_KINDS.contains(kind).then(|| item.to_lowercase());
    }
    let (head, _) = title.split_once(" in ")?;
    let last = head.split_whitespace().last()?;
    (!last.contains("::")).then(|| last.to_lowercase())
}

/// A topic's text is scored by its BEST LINE, not as one bag of words: the
/// answer is usually one row of a table (rivet's `verifies | verified-by |
/// Test verifies a requirement`), and a whole-text bag lets every long topic
/// that mentions the words somewhere tie with it.
fn best_line(body: &str, words: &[String]) -> Option<(u32, String)> {
    let mut best: Option<(u32, String)> = None;
    for line in body.lines() {
        let toks = tokens(line);
        let hit = words.iter().filter(|w| toks.contains(w)).count() as u32;
        if hit > 0 && best.as_ref().is_none_or(|(b, _)| hit > *b) {
            best = Some((hit, snippet_of(line)));
        }
    }
    best.map(|(n, line)| (n * DESC, line))
}

/// Which of the QUESTION's own words one line of a topic holds together.
/// Printed instead of the line: it says why a hit matched — measured, agents
/// dismissed `rivet docs artifact-format` as noise for "verifies" because its
/// title gave no reason — without putting any of the topic's text, which a
/// producer wrote and could carry an injection, in front of the reader.
fn matched_words(line: &str, words: &[String]) -> Vec<String> {
    let toks = tokens(line);
    words.iter().filter(|w| toks.contains(w)).cloned().collect()
}

/// One line, trimmed, cut at a word boundary if it is long — never mid-word.
fn snippet_of(line: &str) -> String {
    let cleaned = crate::help::clean_block(line);
    let line = cleaned.trim();
    if line.chars().count() <= SNIPPET_MAX {
        return line.to_string();
    }
    let mut out = String::new();
    for w in line.split_whitespace() {
        if out.chars().count() + w.chars().count() + 1 > SNIPPET_MAX {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out.push_str(" …");
    out
}

fn base_score(u: &Unit, words: &[String]) -> u32 {
    let name = tokens(&u.name);
    let desc = tokens(&format!("{} {}", u.title, u.desc));
    // A topic's body is scored by `best_line` instead.
    let body = if u.kind == Kind::Topic {
        Vec::new()
    } else {
        tokens(&u.body)
    };
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

fn score(u: &Unit, words: &[String]) -> (u32, Option<String>) {
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
            (NAME + NAMED_TOOL, None)
        } else {
            (0, None)
        };
    }
    let line = if u.kind == Kind::Topic {
        best_line(&u.body, &rest)
    } else {
        None
    };
    let base = base_score(u, &rest) + line.as_ref().map_or(0, |(n, _)| *n);
    if base == 0 {
        return (0, None);
    }
    let snippet = line.map(|(_, l)| l);
    let mut s = base;
    // A subcommand whose own name is a word of the question is very likely
    // the verb asked for: "rivet add requirement test verifies" wants
    // `rivet add`, which otherwise lost to subcommands whose descriptions
    // happened to repeat more of the other words.
    if u.kind == Kind::ToolSubcommand && rest.contains(&u.name.to_lowercase()) {
        s += SUBCOMMAND_NAMED;
    }
    if let Some(item) = &u.item
        && words.contains(item)
    {
        s += EXACT_ITEM;
    }
    if named {
        s += NAMED_TOOL;
    }
    (s, snippet)
}

/// Rank `units` for `query`, best first, ties broken by `(kind, id)`.
pub fn search(units: &[Unit], query: &str, limit: usize) -> Vec<Hit> {
    let words = query_words(query);
    let mut hits: Vec<Hit> = units
        .iter()
        .filter_map(|u| {
            let (s, snippet) = score(u, &words);
            let matched = snippet
                .as_deref()
                .map_or_else(Vec::new, |l| matched_words(l, &words));
            (s > 0).then(|| Hit {
                snippet,
                matched,
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
                read: format!(
                    "varve export-docs --out ./doc --select={}",
                    shell_word(&p.name)
                ),
            });
            continue;
        }
        for page in docpages::pages(p)? {
            // A member path starting with `-` would be read as a flag by
            // `page`; it is left out rather than handed over as a command.
            if page.path.starts_with('-') {
                continue;
            }
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
                read: format!(
                    // `--` ends the options: a name a producer chose can
                    // never be read as a flag, quoted or not.
                    "varve-serve page -- {} {}",
                    shell_word(&p.name),
                    shell_word(&page.path)
                ),
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
        // The PAYLOAD's digest — the file this hit lives in — not the
        // layer manifest digest, which is in the orientation's header.
        // The payload digest stays in `--format json`. In this view it
        // repeated on every hit and two of two eval agents confused it with
        // the layer manifest digest, which the orientation's header states.
        if h.matched.len() > 1 {
            o.push_str(&format!(
                "\n   one line here holds: {}",
                h.matched.join(", ")
            ));
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
            "payload_digest": h.digest,
            "matched_words": h.matched,
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

    /// A topic is scored by its best line, and that line is shown: the row
    /// that answers is one line of a long table.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_topic_ranks_by_its_best_line_and_records_it() {
        let mut table = unit(
            Kind::Topic,
            "topic:rivet:artifact-format",
            "artifact-format",
            "`rivet docs artifact-format`",
            "",
        );
        table.tool = Some("rivet".into());
        table.body = "intro text about artifacts\n| satisfies | satisfied-by | Implements a requirement |\n| verifies | verified-by | Test verifies a requirement |\n".into();
        // A long topic that mentions every word, but never on one line.
        let mut wordy = unit(
            Kind::Topic,
            "topic:rivet:audit",
            "audit",
            "`rivet docs audit`",
            "",
        );
        wordy.tool = Some("rivet".into());
        wordy.body = "a test\nsomething verifies\nevery requirement\nlink here\n".into();
        let hits = search(&[wordy, table], "rivet link test verifies requirement", 5);
        assert_eq!(ids(&hits)[0], "topic:rivet:artifact-format", "{hits:?}");
        assert_eq!(
            hits[0].snippet.as_deref(),
            Some("| verifies | verified-by | Test verifies a requirement |")
        );
    }

    /// A topic hit says which of the question's words one of its lines holds
    /// together — the reason it matched — and prints none of the line.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_topic_hit_names_the_question_words_it_matched_not_its_text() {
        let mut table = unit(
            Kind::Topic,
            "topic:rivet:artifact-format",
            "artifact-format",
            "`rivet docs artifact-format` — YAML artifact file format",
            "",
        );
        table.tool = Some("rivet".into());
        table.body = "| verifies | verified-by | Test verifies a requirement |\n".into();
        let hits = search(&[table], "add requirement link test verifies", 5);
        assert_eq!(hits[0].matched, ["requirement", "test", "verifies"]);
        let ctx = ctx_with(vec![]);
        let md = render_md("q", &ctx, &hits);
        assert!(
            md.contains("one line here holds: requirement, test, verifies"),
            "{md}"
        );
        assert!(
            !md.contains("verified-by"),
            "the line itself is not printed: {md}"
        );
        // a single matched word is no reason worth printing
        let mut one = unit(Kind::Topic, "topic:x:y", "y", "t", "");
        one.body = "a zebra".into();
        let h1 = search(&[one], "zebra", 1);
        assert!(!render_md("q", &ctx, &h1).contains("one line here holds"));
    }

    /// A long line is cut at a word boundary, never inside a word.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_long_snippet_is_cut_between_words() {
        let line = "word ".repeat(60);
        let cut = snippet_of(&line);
        assert!(cut.ends_with(" …"), "{cut}");
        assert!(cut.chars().count() <= SNIPPET_MAX + 2, "{}", cut.len());
        assert!(
            cut.trim_end_matches(" …").split(' ').all(|w| w == "word"),
            "{cut}"
        );
        assert_eq!(snippet_of("  short line  "), "short line");
    }

    /// A function page is not "the" answer to a word; the tool's verb is.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_function_page_does_not_take_the_item_boost() {
        let mut page = unit(
            Kind::DocsPage,
            "docs:fn.sign",
            "v/verify/fn.sign.html",
            "sign in v::verify - Rust",
            "",
        );
        page.item = item_of("v/verify/fn.sign.html", "sign in v::verify - Rust");
        assert_eq!(page.item, None, "fn pages carry no exact item");
        let mut sub = unit(
            Kind::ToolSubcommand,
            "tool:wsc:sub:sign",
            "sign",
            "`wsc sign` — Sign a module",
            "Sign a module",
        );
        sub.tool = Some("wsc".into());
        let hits = search(&[page, sub], "sign wasm module", 5);
        assert_eq!(ids(&hits)[0], "tool:wsc:sub:sign", "{hits:?}");
    }

    /// The subcommand whose name IS a word of the question wins over ones
    /// whose descriptions merely repeat more of the other words.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_subcommand_named_in_the_question_outranks_wordier_neighbours() {
        let mk = |name: &str, desc: &str| {
            let mut u = unit(
                Kind::ToolSubcommand,
                &format!("tool:rivet:sub:{name}"),
                name,
                &format!("`rivet {name}` — {desc}"),
                desc,
            );
            u.tool = Some("rivet".into());
            u
        };
        let add = mk("add", "Add a new artifact to the project");
        let verify = mk(
            "verify",
            "Advance a requirement to verified when it has verifying test evidence",
        );
        let trace = mk(
            "trace-results",
            "Trace a requirement FORWARD to the test results that cover it",
        );
        let hits = search(
            &[verify, trace, add],
            "rivet add requirement test verifies",
            5,
        );
        assert_eq!(ids(&hits)[0], "tool:rivet:sub:add", "{hits:?}");
    }

    /// Names and paths from a layer become shell words, quoted when not
    /// plainly safe, so a `read` command cannot smuggle shell syntax.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn layer_names_become_safe_shell_words() {
        assert_eq!(
            shell_word("varve_core/store/struct.Store.html"),
            "varve_core/store/struct.Store.html"
        );
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("x$(touch PWNED)"), "'x$(touch PWNED)'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word("-rf"), "'-rf'");
        assert_eq!(shell_word(""), "''");
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
        // Body weight is for whole-text units; a TOPIC's body is scored by
        // its best line (see `a_topic_answers_by_its_best_line_and_shows_it`).
        let mut body = unit(Kind::DocsPage, "b", "other2", "t", "");
        body.body = "text about a zebra".into();
        let part = unit(Kind::Topic, "p", "zebras", "t", "");
        let w = vec!["zebra".to_string()];
        assert_eq!(score(&name, &w).0, NAME);
        assert_eq!(score(&desc, &w).0, DESC);
        assert_eq!(score(&body, &w).0, BODY);
        assert_eq!(score(&part, &w).0, PARTIAL);
        assert_eq!(
            score(
                &unit(Kind::Topic, "x", "zeb", "t", ""),
                &["zeb".to_string()]
            )
            .0,
            NAME
        );
        // a two-letter word does not match by substring
        assert_eq!(
            score(
                &unit(Kind::Topic, "y", "rivet", "t", ""),
                &["iv".to_string()]
            )
            .0,
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
            tool_input(
                "meld",
                meld,
                &[(
                    "fusion",
                    "the zebra line\nthe secret paragraph\nesc \u{1b}[31m zebra",
                )],
            ),
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
        // A hit is a POINTER: no line of the topic's text is printed, not
        // even the one that matched (docs text is a prompt-injection surface).
        let json = render_json("zebra", &ctx, &hits);
        let md = render_md("zebra", &ctx, &hits);
        for out in [&json, &md] {
            assert!(!out.contains("zebra line"), "matched text leaked: {out}");
            assert!(!out.contains("secret paragraph"), "text leaked: {out}");
        }
        assert_eq!(hits[0].snippet.as_deref(), Some("the zebra line"));
        assert_eq!(hits[0].matched, ["zebra"]);
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
            "varve export-docs --out ./doc --select=manual"
        );
        assert_eq!(by("docs:manual").digest.as_deref(), Some("sha256:manual"));
        assert_eq!(by("docs:manual").title, "manual handbook");
        assert_eq!(by("docs:manual").desc, "rivet");
        assert_eq!(
            by("docs:site:a.html").read,
            "varve-serve page -- site a.html"
        );
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
            md.contains("layer: 2026.10.1\n") && !md.contains("sha256:meld"),
            "{md}"
        );
        assert!(md.contains("read: `meld fuse --help`\n"), "{md}");
        let v: Value = serde_json::from_str(&render_json("meld fuse", &ctx, &hits)).unwrap();
        assert_eq!(v["hits"][0]["id"], "tool:meld:sub:fuse");
        assert_eq!(v["hits"][0]["payload_digest"], "sha256:meld");
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
