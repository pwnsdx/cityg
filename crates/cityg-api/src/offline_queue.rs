// Offline message queue infrastructure
//
// This module provides message queuing for handling network failures.
// The queue is created and integrated into ApiState, ready for use when
// network failure handling is needed.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

/// Offline message queue for storing messages when network is unavailable
#[derive(Clone)]
pub struct OfflineMessageQueue {
    inner: Arc<Mutex<QueueInner>>,
    notify: Arc<Notify>,
    max_queue_size: usize,
}

struct QueueInner {
    queue: VecDeque<QueuedMessage>,
    is_online: bool,
}

#[derive(Clone, Debug)]
pub struct QueuedMessage {
    pub we_epoch_id: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub sender: Vec<u8>,
    pub timestamp_ms: u64,
    pub retry_count: u32,
    pub last_retry: Option<SystemTime>,
}

impl OfflineMessageQueue {
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueueInner {
                queue: VecDeque::new(),
                is_online: true,
            })),
            notify: Arc::new(Notify::new()),
            max_queue_size,
        }
    }

    /// Queue a message for later delivery
    pub async fn enqueue(&self, message: QueuedMessage) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().await;

        if inner.queue.len() >= self.max_queue_size {
            warn!(
                queue_size = inner.queue.len(),
                max_size = self.max_queue_size,
                "offline queue full, dropping oldest message"
            );
            inner.queue.pop_front();
        }

        debug!(
            we_epoch_id = hex::encode(message.we_epoch_id),
            queue_size = inner.queue.len() + 1,
            "message queued for offline delivery"
        );

        inner.queue.push_back(message);
        self.notify.notify_one();
        Ok(())
    }

    /// Dequeue the next message for delivery
    pub async fn dequeue(&self) -> Option<QueuedMessage> {
        let mut inner = self.inner.lock().await;
        inner.queue.pop_front()
    }

    /// Peek at the next message without removing it
    pub async fn peek(&self) -> Option<QueuedMessage> {
        let inner = self.inner.lock().await;
        inner.queue.front().cloned()
    }

    /// Get current queue size
    pub async fn len(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.queue.len()
    }

    /// Check if queue is empty
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.queue.is_empty()
    }

    /// Set online/offline status
    pub async fn set_online(&self, online: bool) {
        let mut inner = self.inner.lock().await;
        let previous = inner.is_online;
        inner.is_online = online;

        if online && !previous {
            info!("network status changed to online, processing queued messages");
            self.notify.notify_one();
        } else if !online && previous {
            warn!("network status changed to offline");
        }
    }

    /// Check if currently online
    pub async fn is_online(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.is_online
    }

    /// Wait for notification (new message or status change)
    pub async fn wait_for_notification(&self) {
        self.notify.notified().await
    }

    /// Clear all queued messages
    pub async fn clear(&self) {
        let mut inner = self.inner.lock().await;
        let count = inner.queue.len();
        inner.queue.clear();
        info!(cleared_count = count, "offline queue cleared");
    }

    /// Get messages that are ready for retry
    pub async fn get_retry_candidates(&self, max_retry_count: u32) -> Vec<QueuedMessage> {
        let inner = self.inner.lock().await;
        inner
            .queue
            .iter()
            .filter(|msg| msg.retry_count < max_retry_count)
            .cloned()
            .collect()
    }
}

/// Background task to process the offline queue
pub async fn process_offline_queue<F, Fut>(
    queue: OfflineMessageQueue,
    send_fn: F,
    retry_interval: Duration,
    max_retries: u32,
) where
    F: Fn(QueuedMessage) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    info!("starting offline queue processor");

    loop {
        // Wait for either a new message or the retry interval
        tokio::select! {
            _ = queue.wait_for_notification() => {
                debug!("offline queue notification received");
            }
            _ = tokio::time::sleep(retry_interval) => {
                debug!("offline queue retry interval elapsed");
            }
        }

        // Check if we're online before processing
        if !queue.is_online().await {
            debug!("skipping queue processing while offline");
            continue;
        }

        // Process all messages in the queue
        while let Some(mut message) = queue.dequeue().await {
            debug!(
                we_epoch_id = hex::encode(message.we_epoch_id),
                retry_count = message.retry_count,
                "attempting to send queued message"
            );

            match send_fn(message.clone()).await {
                Ok(_) => {
                    info!(
                        we_epoch_id = hex::encode(message.we_epoch_id),
                        "successfully sent queued message"
                    );
                }
                Err(e) => {
                    message.retry_count += 1;
                    message.last_retry = Some(SystemTime::now());

                    if message.retry_count < max_retries {
                        warn!(
                            we_epoch_id = hex::encode(message.we_epoch_id),
                            retry_count = message.retry_count,
                            error = %e,
                            "failed to send queued message, will retry"
                        );
                        // Re-queue the message
                        let _ = queue.enqueue(message).await;
                    } else {
                        warn!(
                            we_epoch_id = hex::encode(message.we_epoch_id),
                            retry_count = message.retry_count,
                            error = %e,
                            "dropping message after max retries"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_enqueue_dequeue() {
        let queue = OfflineMessageQueue::new(10);

        let message = QueuedMessage {
            we_epoch_id: [1u8; 32],
            ciphertext: vec![1, 2, 3],
            sender: vec![4, 5, 6],
            timestamp_ms: 123456,
            retry_count: 0,
            last_retry: None,
        };

        queue.enqueue(message.clone()).await.unwrap();
        assert_eq!(queue.len().await, 1);

        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.we_epoch_id, message.we_epoch_id);
        assert_eq!(queue.len().await, 0);
    }

    #[tokio::test]
    async fn test_queue_max_size() {
        let queue = OfflineMessageQueue::new(3);

        for i in 0..5 {
            let message = QueuedMessage {
                we_epoch_id: [i as u8; 32],
                ciphertext: vec![],
                sender: vec![],
                timestamp_ms: 0,
                retry_count: 0,
                last_retry: None,
            };
            queue.enqueue(message).await.unwrap();
        }

        // Should only have 3 messages (oldest 2 were dropped)
        assert_eq!(queue.len().await, 3);
    }

    #[tokio::test]
    async fn test_online_offline_status() {
        let queue = OfflineMessageQueue::new(10);

        assert!(queue.is_online().await);

        queue.set_online(false).await;
        assert!(!queue.is_online().await);

        queue.set_online(true).await;
        assert!(queue.is_online().await);
    }
}
