// SPDX-License-Identifier: Apache-2.0

use crate::{proto, EngineError, ProofEngine};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex},
};

#[derive(Clone)]
enum ProofValue {
    Single(Vec<u8>),
    Multiple(Vec<Vec<u8>>),
}

enum JobState {
    Running,
    Done(Result<ProofValue, EngineError>),
}

struct Job {
    state: Mutex<JobState>,
    ready: Condvar,
}

impl Job {
    fn running() -> Self {
        Self {
            state: Mutex::new(JobState::Running),
            ready: Condvar::new(),
        }
    }
}

#[derive(Clone)]
pub struct DeduplicatingEngine<E> {
    inner: Arc<E>,
    table: Arc<Mutex<JobTable>>,
    max_jobs: usize,
}

#[derive(Default)]
struct JobTable {
    running: HashMap<[u8; 32], Arc<Job>>,
    completed: HashMap<[u8; 32], ProofValue>,
    completed_order: VecDeque<[u8; 32]>,
}

impl<E> DeduplicatingEngine<E> {
    #[must_use]
    pub fn new(inner: Arc<E>, max_jobs: usize) -> Self {
        Self {
            inner,
            table: Arc::new(Mutex::new(JobTable::default())),
            max_jobs,
        }
    }

    fn run<F>(
        &self,
        key: [u8; 32],
        cache_completed: bool,
        operation: F,
    ) -> Result<ProofValue, EngineError>
    where
        F: FnOnce(&E) -> Result<ProofValue, EngineError>,
    {
        let (job, owner) = {
            let mut table = self
                .table
                .lock()
                .map_err(|_| EngineError::Internal("proof job table is poisoned".into()))?;
            if cache_completed {
                if let Some(value) = table.completed.get(&key) {
                    return Ok(value.clone());
                }
            }
            if let Some(job) = table.running.get(&key) {
                (Arc::clone(job), false)
            } else {
                if table.running.len() >= self.max_jobs {
                    return Err(EngineError::ResourceExhausted(
                        "maximum number of distinct proof jobs is already running".into(),
                    ));
                }
                let job = Arc::new(Job::running());
                table.running.insert(key, Arc::clone(&job));
                (job, true)
            }
        };

        if owner {
            let result = operation(&self.inner);
            {
                let mut state = job
                    .state
                    .lock()
                    .map_err(|_| EngineError::Internal("proof job state is poisoned".into()))?;
                *state = JobState::Done(result.clone());
                job.ready.notify_all();
            }
            let mut table = self
                .table
                .lock()
                .map_err(|_| EngineError::Internal("proof job table is poisoned".into()))?;
            table.running.remove(&key);
            if cache_completed {
                if let Ok(value) = &result {
                    if table.completed.len() >= self.max_jobs {
                        if let Some(oldest) = table.completed_order.pop_front() {
                            table.completed.remove(&oldest);
                        }
                    }
                    table.completed.insert(key, value.clone());
                    table.completed_order.push_back(key);
                }
            }
            result
        } else {
            let mut state = job
                .state
                .lock()
                .map_err(|_| EngineError::Internal("proof job state is poisoned".into()))?;
            loop {
                match &*state {
                    JobState::Running => {
                        state = job.ready.wait(state).map_err(|_| {
                            EngineError::Internal("proof job state is poisoned".into())
                        })?;
                    }
                    JobState::Done(result) => return result.clone(),
                }
            }
        }
    }
}

impl<E: ProofEngine> ProofEngine for DeduplicatingEngine<E> {
    fn latest_provable_height(&self, client: &proto::Client) -> Result<(u64, u64), EngineError> {
        self.inner.latest_provable_height(client)
    }

    fn trust_update_proof(&self, client: &proto::Client) -> Result<Vec<u8>, EngineError> {
        let key = request_key(b"trust", &client.encode_to_vec());
        match self.run(key, false, |inner| {
            inner.trust_update_proof(client).map(ProofValue::Single)
        })? {
            ProofValue::Single(value) => Ok(value),
            ProofValue::Multiple(_) => Err(EngineError::Internal("proof job type mismatch".into())),
        }
    }

    fn state_proof(&self, client: &proto::Client, height: u64) -> Result<Vec<u8>, EngineError> {
        let mut encoded = client.encode_to_vec();
        encoded.extend_from_slice(&height.to_be_bytes());
        let key = request_key(b"state", &encoded);
        match self.run(key, false, |inner| {
            inner.state_proof(client, height).map(ProofValue::Single)
        })? {
            ProofValue::Single(value) => Ok(value),
            ProofValue::Multiple(_) => Err(EngineError::Internal("proof job type mismatch".into())),
        }
    }

    fn packet_proofs(
        &self,
        request: &proto::PacketProofsRequest,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let key = request_key(b"packet", &request.encode_to_vec());
        match self.run(key, true, |inner| {
            inner.packet_proofs(request).map(ProofValue::Multiple)
        })? {
            ProofValue::Multiple(value) => Ok(value),
            ProofValue::Single(_) => Err(EngineError::Internal("proof job type mismatch".into())),
        }
    }
}

fn request_key(domain: &[u8], request: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(request);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;

    struct CountingEngine {
        calls: AtomicUsize,
        started: Mutex<Option<mpsc::Sender<()>>>,
    }

    impl ProofEngine for CountingEngine {
        fn latest_provable_height(
            &self,
            _client: &proto::Client,
        ) -> Result<(u64, u64), EngineError> {
            Ok((1, 2))
        }

        fn trust_update_proof(&self, _client: &proto::Client) -> Result<Vec<u8>, EngineError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut started) = self.started.lock() {
                if let Some(sender) = started.take() {
                    let _ = sender.send(());
                }
            }
            thread::sleep(std::time::Duration::from_millis(50));
            Ok(vec![7])
        }

        fn state_proof(
            &self,
            _client: &proto::Client,
            _height: u64,
        ) -> Result<Vec<u8>, EngineError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![8])
        }

        fn packet_proofs(
            &self,
            _request: &proto::PacketProofsRequest,
        ) -> Result<Vec<Vec<u8>>, EngineError> {
            Ok(vec![vec![9]])
        }
    }

    #[test]
    fn matching_in_flight_requests_share_one_execution() {
        let (started_tx, started_rx) = mpsc::channel();
        let inner = Arc::new(CountingEngine {
            calls: AtomicUsize::new(0),
            started: Mutex::new(Some(started_tx)),
        });
        let engine = Arc::new(DeduplicatingEngine::new(Arc::clone(&inner), 4));
        let client = proto::Client {
            chain_id: "1".into(),
            client_id: "client-0".into(),
        };
        let first = {
            let engine = Arc::clone(&engine);
            let client = client.clone();
            thread::spawn(move || engine.trust_update_proof(&client))
        };
        assert!(started_rx.recv().is_ok());
        let second = {
            let engine = Arc::clone(&engine);
            let client = client.clone();
            thread::spawn(move || engine.trust_update_proof(&client))
        };
        assert_eq!(first.join().ok(), Some(Ok(vec![7])));
        assert_eq!(second.join().ok(), Some(Ok(vec![7])));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_proofs_are_not_reused_after_trust_can_change() {
        let inner = Arc::new(CountingEngine {
            calls: AtomicUsize::new(0),
            started: Mutex::new(None),
        });
        let engine = DeduplicatingEngine::new(Arc::clone(&inner), 2);
        let client = proto::Client {
            chain_id: "1".into(),
            client_id: "client-0".into(),
        };
        assert_eq!(engine.state_proof(&client, 7), Ok(vec![8]));
        assert_eq!(engine.state_proof(&client, 7), Ok(vec![8]));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn trust_updates_are_not_reused_after_completion() {
        let inner = Arc::new(CountingEngine {
            calls: AtomicUsize::new(0),
            started: Mutex::new(None),
        });
        let engine = DeduplicatingEngine::new(Arc::clone(&inner), 2);
        let client = proto::Client {
            chain_id: "1".into(),
            client_id: "client-0".into(),
        };
        assert_eq!(engine.trust_update_proof(&client), Ok(vec![7]));
        assert_eq!(engine.trust_update_proof(&client), Ok(vec![7]));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn height_and_packet_requests_preserve_result_shapes() {
        let inner = Arc::new(CountingEngine {
            calls: AtomicUsize::new(0),
            started: Mutex::new(None),
        });
        let engine = DeduplicatingEngine::new(inner, 2);
        let client = proto::Client {
            chain_id: "1".into(),
            client_id: "client-0".into(),
        };
        assert_eq!(engine.latest_provable_height(&client), Ok((1, 2)));
        let request = proto::PacketProofsRequest {
            client: Some(client),
            height: 1,
            kind: 1,
            packets: vec![proto::Packet::default()],
        };
        assert_eq!(engine.packet_proofs(&request), Ok(vec![vec![9]]));
        assert_eq!(engine.packet_proofs(&request), Ok(vec![vec![9]]));
        assert_ne!(request_key(b"packet", b"a"), request_key(b"packet", b"b"));
        assert_ne!(request_key(b"packet", b"a"), request_key(b"state", b"a"));
    }

    #[test]
    fn distinct_running_jobs_are_bounded() {
        let (started_tx, started_rx) = mpsc::channel();
        let inner = Arc::new(CountingEngine {
            calls: AtomicUsize::new(0),
            started: Mutex::new(Some(started_tx)),
        });
        let engine = Arc::new(DeduplicatingEngine::new(inner, 1));
        let first_client = proto::Client {
            chain_id: "1".into(),
            client_id: "first".into(),
        };
        let first = {
            let engine = Arc::clone(&engine);
            thread::spawn(move || engine.trust_update_proof(&first_client))
        };
        assert!(started_rx.recv().is_ok());
        let second_client = proto::Client {
            chain_id: "1".into(),
            client_id: "second".into(),
        };
        assert!(matches!(
            engine.trust_update_proof(&second_client),
            Err(EngineError::ResourceExhausted(_))
        ));
        assert_eq!(first.join().ok(), Some(Ok(vec![7])));
    }
}
