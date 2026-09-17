//! Protocol tree with byte-range mapping for hex highlight.

#[derive(Debug, Clone)]
pub struct ProtoNode {
    pub label: String,
    pub value: String,
    pub offset: usize,
    pub len: usize,
    pub children: Vec<usize>,
    pub expanded: bool,
}

impl ProtoNode {
    pub fn display(&self) -> String {
        if self.value.is_empty() {
            self.label.clone()
        } else {
            format!("{}: {}", self.label, self.value)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtoTree {
    nodes: Vec<ProtoNode>,
    roots: Vec<usize>,
}

impl ProtoTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn add_root(&mut self, label: impl Into<String>, offset: usize, len: usize) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(ProtoNode {
            label: label.into(),
            value: String::new(),
            offset,
            len,
            children: Vec::new(),
            expanded: true,
        });
        self.roots.push(idx);
        idx
    }

    pub fn add_child(
        &mut self,
        parent: usize,
        label: impl Into<String>,
        value: impl Into<String>,
        offset: usize,
        len: usize,
    ) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(ProtoNode {
            label: label.into(),
            value: value.into(),
            offset,
            len,
            children: Vec::new(),
            expanded: true,
        });
        if let Some(p) = self.nodes.get_mut(parent) {
            p.children.push(idx);
        }
        idx
    }

    pub fn add_section(
        &mut self,
        parent: usize,
        label: impl Into<String>,
        offset: usize,
        len: usize,
    ) -> usize {
        self.add_child(parent, label, "", offset, len)
    }

    pub fn node(&self, idx: usize) -> Option<&ProtoNode> {
        self.nodes.get(idx)
    }

    pub fn node_mut(&mut self, idx: usize) -> Option<&mut ProtoNode> {
        self.nodes.get_mut(idx)
    }

    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    /// Flatten visible nodes (respecting expanded) as (depth, node_index).
    pub fn visible(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for &r in &self.roots {
            self.walk_visible(r, 0, &mut out);
        }
        out
    }

    fn walk_visible(&self, idx: usize, depth: usize, out: &mut Vec<(usize, usize)>) {
        out.push((depth, idx));
        let Some(n) = self.nodes.get(idx) else {
            return;
        };
        if n.expanded {
            for &c in &n.children {
                self.walk_visible(c, depth + 1, out);
            }
        }
    }

    pub fn toggle(&mut self, idx: usize) {
        if let Some(n) = self.nodes.get_mut(idx) {
            if !n.children.is_empty() {
                n.expanded = !n.expanded;
            }
        }
    }
}
