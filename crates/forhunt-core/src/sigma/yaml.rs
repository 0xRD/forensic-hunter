//! A YAML tree that keeps every scalar as its text.
//!
//! Sigma values must be compared as written: YAML 1.2 would turn the plain
//! scalar `0x1410` (a Windows access mask) into the integer 5136 and `0012`
//! into 12, which no longer match the event's text. Only plain `null`, `~` and
//! empty scalars become [`Node::Null`]; everything else stays a string.

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Null,
    Str(String),
    Seq(Vec<Node>),
    /// Keys in document order.
    Map(Vec<(String, Node)>),
}

impl Node {
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Node::Str(s) => Some(s),
            _ => None,
        }
    }

    /// A string, or the strings of a sequence.
    pub fn strings(&self) -> Vec<String> {
        match self {
            Node::Str(s) => vec![s.clone()],
            Node::Seq(v) => v
                .iter()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }
}

enum Frame {
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>, Option<String>),
}

#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    docs: Vec<Node>,
    /// Anchored nodes, for aliases.
    anchors: Vec<(usize, Node, usize)>,
    pending_anchor: Vec<usize>,
    /// Nodes added through aliases so far (bounded: nested aliases double at
    /// each level, a few lines would otherwise fill the memory).
    alias_nodes: usize,
    too_big: bool,
}

/// Most nodes aliases may add to one file (a Sigma rule uses a handful).
const MAX_ALIAS_NODES: usize = 100_000;

fn size(n: &Node) -> usize {
    match n {
        Node::Null | Node::Str(_) => 1,
        Node::Seq(v) => 1 + v.iter().map(size).sum::<usize>(),
        Node::Map(m) => 1 + m.iter().map(|(_, v)| size(v)).sum::<usize>(),
    }
}

impl Builder {
    fn push(&mut self, n: Node) {
        match self.stack.last_mut() {
            None => self.docs.push(n),
            Some(Frame::Seq(v)) => v.push(n),
            Some(Frame::Map(m, key)) => match key.take() {
                None => {
                    let k = match n {
                        Node::Str(s) => s,
                        Node::Null => String::new(),
                        // Complex keys do not occur in Sigma; keep a marker.
                        _ => "<complex key>".to_string(),
                    };
                    *key = Some(k);
                }
                Some(k) => m.push((k, n)),
            },
        }
    }

    fn close(&mut self, aid: usize, n: Node) {
        if aid > 0 {
            self.anchors.push((aid, n.clone(), size(&n)));
        }
        self.push(n);
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, _mark: Marker) {
        match ev {
            Event::Scalar(v, style, aid, _tag) => {
                let n = if style == TScalarStyle::Plain
                    && matches!(v.as_str(), "" | "~" | "null" | "Null" | "NULL")
                {
                    Node::Null
                } else {
                    Node::Str(v)
                };
                self.close(aid, n);
            }
            Event::SequenceStart(aid, _) => {
                self.pending_anchor.push(aid);
                self.stack.push(Frame::Seq(Vec::new()));
            }
            Event::MappingStart(aid, _) => {
                self.pending_anchor.push(aid);
                self.stack.push(Frame::Map(Vec::new(), None));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let aid = self.pending_anchor.pop().unwrap_or(0);
                let n = match self.stack.pop() {
                    Some(Frame::Seq(v)) => Node::Seq(v),
                    Some(Frame::Map(m, _)) => Node::Map(m),
                    None => return,
                };
                self.close(aid, n);
            }
            Event::Alias(id) => {
                let found = self.anchors.iter().rev().find(|(a, _, _)| *a == id);
                let n = match found {
                    Some((_, n, k)) if !self.too_big => {
                        self.alias_nodes = self.alias_nodes.saturating_add(*k);
                        if self.alias_nodes > MAX_ALIAS_NODES {
                            self.too_big = true;
                            Node::Null
                        } else {
                            n.clone()
                        }
                    }
                    _ => Node::Null,
                };
                self.push(n);
            }
            _ => {}
        }
    }
}

/// Parses every document of `text`.
pub fn parse(text: &str) -> Result<Vec<Node>, String> {
    let mut b = Builder::default();
    let mut p = Parser::new_from_str(text.trim_start_matches('\u{feff}'));
    p.load(&mut b, true).map_err(|e| e.to_string())?;
    if b.too_big {
        return Err(format!(
            "aliases expand to more than {MAX_ALIAS_NODES} nodes"
        ));
    }
    Ok(b.docs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_stay_text() {
        let d = parse("a: 0x1410\nb: 0012\nc: ~\nd: 'null'\ne: [1, true]\nf:\n  - x: 1\n").unwrap();
        let n = &d[0];
        assert_eq!(n.get("a"), Some(&Node::Str("0x1410".into())));
        assert_eq!(n.get("b"), Some(&Node::Str("0012".into())));
        assert_eq!(n.get("c"), Some(&Node::Null));
        assert_eq!(n.get("d"), Some(&Node::Str("null".into())));
        assert_eq!(n.get("e").unwrap().strings(), ["1", "true"]);
        assert!(matches!(n.get("f"), Some(Node::Seq(v)) if v.len() == 1));
    }

    #[test]
    fn multi_doc_and_alias() {
        let d = parse("a: &x [1, 2]\nb: *x\n---\nc: 3\n").unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].get("b").unwrap().strings(), ["1", "2"]);
    }

    #[test]
    fn alias_bomb_is_refused() {
        let mut y = String::from("l0: &a0 [x, x]\n");
        for i in 1..40 {
            y += &format!("l{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1);
        }
        assert!(parse(&y).unwrap_err().contains("aliases"));
    }
}
