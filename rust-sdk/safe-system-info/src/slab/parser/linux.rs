/*
 * Original code from uutils procps package
 * Original source: https://github.com/uutils/procps/blob/main/src/uu/slabtop/src/parse.rs
 * Original Copyright (c) 2024 uutils
 * Original Licensed under MIT License - see `LICENSE.md` for full license text
 *
 * MODIFICATIONS:
 * - Removed unused functions
 * - Changed method visibility from pub to pub(crate)
 * - No modifications to existing logic
 *
 * Parser implementation for /proc/slabinfo format version 2.1
 */
#[derive(Debug, Default)]
pub(crate) struct SlabInfo {
    pub(crate) meta: Vec<String>,
    pub(crate) data: Vec<(String, Vec<u64>)>,
}

impl SlabInfo {
    pub(crate) fn parse(content: &str) -> Option<SlabInfo> {
        let mut lines: Vec<&str> = content.lines().collect();

        let _ = parse_version(lines.remove(0))?;
        let meta = parse_meta(lines.remove(0));
        let data: Vec<(String, Vec<u64>)> = lines.into_iter().filter_map(parse_data).collect();

        Some(SlabInfo { meta, data })
    }

    pub(crate) fn fetch(&self, name: &str, meta: &str) -> Option<u64> {
        // fetch meta's offset
        let offset = self.offset(meta)?;

        let (_, item) = self.data.iter().find(|(key, _)| key.eq(name))?;

        item.get(offset).copied()
    }

    pub(crate) fn names(&self) -> Vec<&String> {
        self.data.iter().map(|(k, _)| k).collect()
    }

    fn offset(&self, meta: &str) -> Option<usize> {
        self.meta.iter().position(|it| it.eq(meta))
    }

    /////////////////////////////////// helpers ///////////////////////////////////

    #[inline]
    pub(crate) fn total(&self, meta: &str) -> u64 {
        let Some(offset) = self.offset(meta) else {
            return 0;
        };

        self.data
            .iter()
            .filter_map(|(_, data)| data.get(offset))
            .sum::<u64>()
    }

    pub(crate) fn object_minimum(&self) -> u64 {
        let Some(offset) = self.offset("objsize") else {
            return 0;
        };

        match self
            .data
            .iter()
            .filter_map(|(_, data)| data.get(offset))
            .min()
        {
            Some(min) => *min,
            None => 0,
        }
    }

    pub(crate) fn object_maximum(&self) -> u64 {
        let Some(offset) = self.offset("objsize") else {
            return 0;
        };

        match self
            .data
            .iter()
            .filter_map(|(_, data)| data.get(offset))
            .max()
        {
            Some(max) => *max,
            None => 0,
        }
    }

    pub(crate) fn total_active_objs(&self) -> u64 {
        self.total("active_objs")
    }

    pub(crate) fn total_objs(&self) -> u64 {
        self.total("num_objs")
    }

    pub(crate) fn total_active_slabs(&self) -> u64 {
        self.total("active_slabs")
    }

    pub(crate) fn total_slabs(&self) -> u64 {
        self.total("num_slabs")
    }

    pub(crate) fn total_active_size(&self) -> u64 {
        self.names()
            .iter()
            .map(|name| {
                self.fetch(name, "active_objs").unwrap_or_default()
                    * self.fetch(name, "objsize").unwrap_or_default()
            })
            .sum::<u64>()
    }

    pub(crate) fn total_size(&self) -> u64 {
        self.names()
            .iter()
            .map(|name| {
                self.fetch(name, "num_objs").unwrap_or_default()
                    * self.fetch(name, "objsize").unwrap_or_default()
            })
            .sum::<u64>()
    }
}

pub(crate) fn parse_version(line: &str) -> Option<String> {
    line.replace(':', " ")
        .split_whitespace()
        .last()
        .map(String::from)
}

pub(crate) fn parse_meta(line: &str) -> Vec<String> {
    line.replace(['#', ':'], " ")
        .split_whitespace()
        .filter(|it| it.starts_with('<') && it.ends_with('>'))
        .map(|it| it.replace(['<', '>'], ""))
        .collect()
}

pub(crate) fn parse_data(line: &str) -> Option<(String, Vec<u64>)> {
    let split: Vec<String> = line
        .replace(':', " ")
        .split_whitespace()
        .map(String::from)
        .collect();

    split.first().map(|name| {
        (
            name.clone(),
            split
                .clone()
                .into_iter()
                .flat_map(|it| it.parse::<u64>())
                .collect(),
        )
    })
}
