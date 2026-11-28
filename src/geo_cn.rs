//! Provinces of mainland China from the ip2region databases
//! (<https://github.com/lionsoul2014/ip2region>, Apache-2.0 / MIT).
//!
//! GeoLite2 knows the province of only a small part of China's address
//! space (about one address in six; none of Jiangsu Telecom's resolvers,
//! for one), so a steering rule by province mostly never matched. The
//! ip2region data covers nearly all of it. Its `.xdb` files (format 3, one
//! for IPv4 and one for IPv6) are read in place (memory-mapped):
//!
//! - 256 bytes of header: version (u16, 3), index policy, creation time,
//!   first and last segment index entry, IP version (4 or 6), pointer size;
//! - a vector index of 256 × 256 entries (u32 start, u32 end, little
//!   endian) for the first two bytes of an address;
//! - segment index entries: start and end address (IPv4: u32 little
//!   endian; IPv6: 16 bytes in network order), u16 length and u32 offset
//!   of the region text `国家|省份|城市|运营商|ISO 代码`.

use std::net::IpAddr;
use std::path::Path;

const HEADER: usize = 256;
const VECTOR: usize = 256 * 256 * 8;

pub struct Xdb {
    map: memmap2::Mmap,
    v6: bool,
}

impl Xdb {
    pub fn open(path: &Path) -> anyhow::Result<Xdb> {
        let file = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("cannot open {}: {e}", path.display()))?;
        // SAFETY: the databases are replaced by rename, never written in place.
        let map = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| anyhow::anyhow!("cannot map {}: {e}", path.display()))?;
        Self::from_map(map).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    fn from_map(map: memmap2::Mmap) -> anyhow::Result<Xdb> {
        if map.len() <= HEADER + VECTOR {
            anyhow::bail!("too short for an ip2region database");
        }
        let u16_at = |o: usize| u16::from_le_bytes([map[o], map[o + 1]]);
        let v6 = match (u16_at(0), u16_at(16)) {
            (2, _) | (3, 4) => false,
            (3, 6) => true,
            (version, ip) => anyhow::bail!("not an ip2region database this build reads (structure {version}, IP version {ip})"),
        };
        Ok(Xdb { map, v6 })
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// The region text for `ip`, if this database has it.
    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        let b = &self.map[..];
        let (key, bytes): (Vec<u8>, usize) = match (ip, self.v6) {
            (IpAddr::V4(a), false) => (a.octets().to_vec(), 4),
            (IpAddr::V6(a), true) => (a.octets().to_vec(), 16),
            _ => return None,
        };
        let u32_at = |o: usize| -> Option<u32> { Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?)) };
        let idx = HEADER + key[0] as usize * 256 * 8 + key[1] as usize * 8;
        let (start, end) = (u32_at(idx)? as usize, u32_at(idx + 4)? as usize);
        if start == 0 || end < start {
            return None;
        }
        let entry = 2 * bytes + 6;
        let (mut lo, mut hi) = (0usize, (end - start) / entry);
        while lo <= hi {
            let mid = (lo + hi) / 2;
            let p = start + mid * entry;
            let seg = b.get(p..p + entry)?;
            let (first, last) = if self.v6 {
                (seg[..16].to_vec(), seg[16..32].to_vec())
            } else {
                // stored little endian: turn into network order to compare
                let mut f = seg[..4].to_vec();
                let mut l = seg[4..8].to_vec();
                f.reverse();
                l.reverse();
                (f, l)
            };
            if key < first {
                if mid == 0 {
                    return None;
                }
                hi = mid - 1;
            } else if key > last {
                lo = mid + 1;
            } else {
                let len = u16::from_le_bytes([seg[2 * bytes], seg[2 * bytes + 1]]) as usize;
                let at = u32::from_le_bytes(seg[2 * bytes + 2..2 * bytes + 6].try_into().ok()?) as usize;
                return std::str::from_utf8(b.get(at..at + len)?).ok();
            }
        }
        None
    }
}

/// ISO 3166-2:CN code of a province as ip2region names it (the codes
/// GeoLite2 uses as well).
pub fn province_code(name: &str) -> Option<&'static str> {
    let short = name.trim_end_matches("特别行政区").trim_end_matches('省').trim_end_matches('市');
    Some(match short {
        "北京" => "BJ",
        "天津" => "TJ",
        "河北" => "HE",
        "山西" => "SX",
        "内蒙古" => "NM",
        "辽宁" => "LN",
        "吉林" => "JL",
        "黑龙江" => "HL",
        "上海" => "SH",
        "江苏" => "JS",
        "浙江" => "ZJ",
        "安徽" => "AH",
        "福建" => "FJ",
        "江西" => "JX",
        "山东" => "SD",
        "河南" => "HA",
        "湖北" => "HB",
        "湖南" => "HN",
        "广东" => "GD",
        "广西" => "GX",
        "海南" => "HI",
        "重庆" => "CQ",
        "四川" => "SC",
        "贵州" => "GZ",
        "云南" => "YN",
        "西藏" => "XZ",
        "陕西" => "SN",
        "甘肃" => "GS",
        "青海" => "QH",
        "宁夏" => "NX",
        "新疆" => "XJ",
        _ => return None,
    })
}

/// What ip2region says about a mainland address: province code and the
/// operator's name (`电信`, `联通`, `移动` …).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CnPlace {
    pub region: Option<&'static str>,
    pub isp: Option<String>,
}

/// Parse a region text; `None` unless it is a mainland Chinese address.
pub fn parse(text: &str) -> Option<CnPlace> {
    let f: Vec<&str> = text.split('|').collect();
    // `国家|省份|城市|运营商|ISO`; older data had a fifth field (`区域`) after the country
    if f.len() != 5 {
        return None;
    }
    let new_layout = f[4] == "0" || (f[4].len() == 2 && f[4].bytes().all(|b| b.is_ascii_uppercase()));
    let (country, province, isp, iso) = if new_layout { (f[0], f[1], f[3], f[4]) } else { (f[0], f[2], f[4], "") };
    if iso.trim() != "CN" && country != "中国" {
        return None;
    }
    let region = province_code(province);
    let isp = Some(isp.trim()).filter(|s| !s.is_empty() && *s != "0").map(String::from);
    Some(CnPlace { region, isp })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provinces_and_texts() {
        assert_eq!(province_code("江苏省"), Some("JS"));
        assert_eq!(province_code("上海市"), Some("SH"));
        assert_eq!(province_code("内蒙古"), Some("NM"));
        assert_eq!(province_code("香港特别行政区"), None);
        assert_eq!(province_code("0"), None);
        assert_eq!(parse("中国|江苏省|南京市|电信|CN"), Some(CnPlace { region: Some("JS"), isp: Some("电信".into()) }));
        assert_eq!(parse("中国|0|0|0|CN"), Some(CnPlace { region: None, isp: None }));
        assert_eq!(parse("United States|California|Mountain View|Google LLC|US"), None);
        assert_eq!(parse("Reserved|Reserved|Reserved|0|0"), None);
        // the layout of ip2region 2.x: 国家|区域|省份|城市|运营商
        assert_eq!(parse("中国|0|浙江省|杭州市|电信"), Some(CnPlace { region: Some("ZJ"), isp: Some("电信".into()) }));
    }

    /// A small database in the real layout: two IPv4 segments.
    #[test]
    fn reads_the_xdb_layout() {
        let regions = ["中国|江苏省|南京市|电信|CN", "中国|山东省|济南市|联通|CN"];
        let mut data = vec![0u8; HEADER + VECTOR];
        data[0..2].copy_from_slice(&3u16.to_le_bytes());
        data[16..18].copy_from_slice(&4u16.to_le_bytes());
        let mut offsets = Vec::new();
        for r in regions {
            offsets.push((data.len() as u32, r.len() as u16));
            data.extend_from_slice(r.as_bytes());
        }
        let segs = [([198u8, 51, 0, 0], [198u8, 51, 127, 255], 0), ([198u8, 51, 128, 0], [198u8, 51, 255, 255], 1)];
        let start = data.len() as u32;
        for (first, last, i) in segs {
            data.extend_from_slice(&u32::from_be_bytes(first).to_le_bytes());
            data.extend_from_slice(&u32::from_be_bytes(last).to_le_bytes());
            data.extend_from_slice(&offsets[i].1.to_le_bytes());
            data.extend_from_slice(&offsets[i].0.to_le_bytes());
        }
        let end = data.len() as u32 - 14;
        let idx = HEADER + 198 * 256 * 8 + 51 * 8;
        data[idx..idx + 4].copy_from_slice(&start.to_le_bytes());
        data[idx + 4..idx + 8].copy_from_slice(&end.to_le_bytes());
        let path = std::env::temp_dir().join(format!("fucf-xdb-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, &data).unwrap();
        let db = Xdb::open(&path).unwrap();
        assert!(!db.is_v6());
        assert_eq!(db.lookup("198.51.20.7".parse().unwrap()), Some(regions[0]));
        assert_eq!(db.lookup("198.51.200.1".parse().unwrap()), Some(regions[1]));
        assert_eq!(db.lookup("198.52.0.1".parse().unwrap()), None);
        assert_eq!(db.lookup("::1".parse().unwrap()), None);
        let _ = std::fs::remove_file(path);
    }
}
