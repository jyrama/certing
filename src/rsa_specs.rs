use clap::ValueEnum;

/// Standard RSA key sizes in bits
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum RsaKeySize {
    /// 2048 bits - Older minimum recommended size for general use
    Size2048 = 2048,
    /// 3072 bits - New default with increased security margin
    Size3072 = 3072,
    /// 4096 bits - Strong security, common for important keys
    Size4096 = 4096,
    /// 7680 bits - Very strong security (slower)
    Size7680 = 7680,
    /// 15360 bits - Extremely strong security (much slower)
    Size15360 = 15360,
}

impl Default for RsaKeySize {
    fn default() -> Self {
        Self::Size3072
    }
}

impl RsaKeySize {
    /// Get the bit size as a u32
    pub fn bits(self) -> u32 {
        self as u32
    }
}
