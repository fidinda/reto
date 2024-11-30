

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub ms_since_1970: u64
}

impl Timestamp {
    pub fn adding(&self, ms: u64) -> Self {
        Self { ms_since_1970: self.ms_since_1970.saturating_add(ms) }
    }

    pub fn removing(&self, ms: u64) -> Self {
        Self { ms_since_1970: self.ms_since_1970.saturating_sub(ms) }
    }

    pub fn difference(&self, other: &Self) -> Option<u64> {
        self.ms_since_1970.checked_sub(other.ms_since_1970)
    }

    pub fn min(&self, other: Self) -> Self {
        Timestamp {
            ms_since_1970: self.ms_since_1970.min(other.ms_since_1970)
        }
    }

    pub fn max(&self, other: Self) -> Self {
        Timestamp {
            ms_since_1970: self.ms_since_1970.max(other.ms_since_1970)
        }
    }
}
