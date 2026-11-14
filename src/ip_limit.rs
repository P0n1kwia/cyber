use std::{collections::HashMap, net::IpAddr, sync::Mutex};

/// Tyle nieudanych logowań z jednego adresu IP (niezależnie od loginu) wolno wykonać w oknie czasowym.
pub const IP_MAX_FAILURES: u32 = 10;
pub const IP_WINDOW_SECS: i64 = 15 * 60;


#[derive(Default)]
pub struct IpLimiter {
    failures: Mutex<HashMap<IpAddr, (u32, i64)>>,
}

impl IpLimiter {
    pub fn blocked_for(&self, ip: IpAddr, now: i64) -> Option<i64> {
        let map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&ip) {
            Some(&(count, start)) if count >= IP_MAX_FAILURES && now - start < IP_WINDOW_SECS => {
                Some(start + IP_WINDOW_SECS - now)
            }
            _ => None,
        }
    }

    pub fn record_failure(&self, ip: IpAddr, now: i64) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, &mut (_, start)| now - start < IP_WINDOW_SECS); // wygasłe okna znikają
        map.entry(ip).or_insert((0, now)).0 += 1;
    }
}
