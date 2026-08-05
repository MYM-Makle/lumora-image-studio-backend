use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// 同一用户的在线状态在该窗口内只落库一次。
const PRESENCE_WINDOW: Duration = Duration::from_secs(60);
/// 超过该规模时顺带清理过期条目，避免长期运行后无界增长。
const PRUNE_THRESHOLD: usize = 4096;

#[derive(Default)]
struct Records {
    /// user_id -> 上次把 last_seen_at 写入数据库的时刻
    last_seen: HashMap<String, Instant>,
    /// user_id -> 已写入 activity_days 的日期（跨日时被覆盖，故内存与用户数同阶）
    activity_day: HashMap<String, String>,
    /// api key 哈希 -> 上次写入 last_used 的时刻
    api_key_used: HashMap<String, Instant>,
}

/// 认证路径的写放大节流器（OPT-03）。
///
/// `user_from_headers` 原本每次认证都会执行 1 次 `UPDATE users` 与 1 次
/// `INSERT ... ON CONFLICT` 到 `activity_days`。前端在生图期间以固定 1 秒间隔轮询
/// 任务状态，单次生图即可产生数十次认证、上百次写事务，与全局写锁叠加会拖慢所有读请求。
///
/// 这里在进程内记忆最近一次落库时间，把高频写压缩成每用户每分钟一次。
/// 代价是 `last_seen_at` 最多滞后 `PRESENCE_WINDOW`，对"最近活跃"这类展示用途可以接受。
#[derive(Clone, Default)]
pub struct PresenceThrottle {
    records: Arc<Mutex<Records>>,
}

impl PresenceThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否需要把该用户的 `last_seen_at` 落库。
    pub fn should_record_last_seen(&self, user_id: &str) -> bool {
        self.check_window(user_id, Instant::now(), |records| &mut records.last_seen)
    }

    /// 是否需要为该用户写入当日的 `activity_days` 记录。
    ///
    /// 同一用户同一天只返回一次 true；跨日时旧日期被覆盖，因此不会随天数增长。
    pub fn should_record_activity_day(&self, user_id: &str, date: &str) -> bool {
        let Ok(mut records) = self.records.lock() else {
            // 锁中毒时退化为"总是落库"，保证数据不丢。
            return true;
        };
        match records.activity_day.get(user_id) {
            Some(recorded) if recorded == date => false,
            _ => {
                records
                    .activity_day
                    .insert(user_id.to_owned(), date.to_owned());
                true
            }
        }
    }

    /// 是否需要把该 API Key 的 `last_used` 落库。
    pub fn should_record_api_key_use(&self, key_hash: &str) -> bool {
        self.check_window(key_hash, Instant::now(), |records| {
            &mut records.api_key_used
        })
    }

    pub fn forget_last_seen(&self, user_id: &str) {
        if let Ok(mut records) = self.records.lock() {
            records.last_seen.remove(user_id);
        }
    }

    pub fn forget_activity_day(&self, user_id: &str, date: &str) {
        if let Ok(mut records) = self.records.lock() {
            if records
                .activity_day
                .get(user_id)
                .is_some_and(|recorded| recorded == date)
            {
                records.activity_day.remove(user_id);
            }
        }
    }

    pub fn forget_api_key_use(&self, key_hash: &str) {
        if let Ok(mut records) = self.records.lock() {
            records.api_key_used.remove(key_hash);
        }
    }

    fn check_window(
        &self,
        key: &str,
        now: Instant,
        select: impl Fn(&mut Records) -> &mut HashMap<String, Instant>,
    ) -> bool {
        let Ok(mut records) = self.records.lock() else {
            return true;
        };
        let map = select(&mut records);
        if map
            .get(key)
            .is_some_and(|recorded| now.duration_since(*recorded) < PRESENCE_WINDOW)
        {
            return false;
        }
        map.insert(key.to_owned(), now);
        if map.len() > PRUNE_THRESHOLD {
            map.retain(|_, recorded| now.duration_since(*recorded) < PRESENCE_WINDOW);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_last_seen_once_per_window() {
        let throttle = PresenceThrottle::new();
        assert!(throttle.should_record_last_seen("user-1"));
        assert!(!throttle.should_record_last_seen("user-1"));
        assert!(!throttle.should_record_last_seen("user-1"));
        // 不同用户互不影响
        assert!(throttle.should_record_last_seen("user-2"));
    }

    #[test]
    fn records_last_seen_again_after_window_elapses() {
        let throttle = PresenceThrottle::new();
        let now = Instant::now();
        assert!(throttle.check_window("user-1", now, |records| &mut records.last_seen));
        let inside = now + PRESENCE_WINDOW - Duration::from_secs(1);
        assert!(!throttle.check_window("user-1", inside, |records| &mut records.last_seen));
        let outside = now + PRESENCE_WINDOW + Duration::from_secs(1);
        assert!(throttle.check_window("user-1", outside, |records| &mut records.last_seen));
    }

    #[test]
    fn records_one_activity_day_per_user_per_date() {
        let throttle = PresenceThrottle::new();
        assert!(throttle.should_record_activity_day("user-1", "2026-08-04"));
        assert!(!throttle.should_record_activity_day("user-1", "2026-08-04"));
        // 跨日重新落库
        assert!(throttle.should_record_activity_day("user-1", "2026-08-05"));
        assert!(!throttle.should_record_activity_day("user-1", "2026-08-05"));
        // 每个用户只保留一条，内存与用户数同阶而非与天数同阶
        assert_eq!(throttle.records.lock().unwrap().activity_day.len(), 1);
    }

    #[test]
    fn prunes_expired_entries_once_over_threshold() {
        let throttle = PresenceThrottle::new();
        let start = Instant::now();
        for index in 0..=PRUNE_THRESHOLD {
            throttle.check_window(&format!("user-{index}"), start, |records| {
                &mut records.last_seen
            });
        }
        assert!(throttle.records.lock().unwrap().last_seen.len() > PRUNE_THRESHOLD);

        // 窗口过期后再有一次调用即触发清理，只留下这一条新鲜记录。
        let later = start + PRESENCE_WINDOW + Duration::from_secs(1);
        throttle.check_window("user-fresh", later, |records| &mut records.last_seen);
        assert_eq!(throttle.records.lock().unwrap().last_seen.len(), 1);
    }

    #[test]
    fn failed_persistence_can_be_retried() {
        let throttle = PresenceThrottle::new();
        assert!(throttle.should_record_last_seen("user-1"));
        throttle.forget_last_seen("user-1");
        assert!(throttle.should_record_last_seen("user-1"));

        assert!(throttle.should_record_activity_day("user-1", "2026-08-05"));
        throttle.forget_activity_day("user-1", "2026-08-05");
        assert!(throttle.should_record_activity_day("user-1", "2026-08-05"));

        assert!(throttle.should_record_api_key_use("hash-1"));
        throttle.forget_api_key_use("hash-1");
        assert!(throttle.should_record_api_key_use("hash-1"));
    }
}
