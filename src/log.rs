//! Non-blocking stdout log writer for `tracing_subscriber`.
//!
//! Uses a bounded `sync_channel` and `try_send` so Tokio worker threads never
//! block on stdout/journald pipe backpressure (zero external dependencies).

use std::io::{self, Write};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use tracing_subscriber::fmt::MakeWriter;

const DEFAULT_LOG_CAP: usize = 4096;

#[derive(Clone)]
pub struct NonBlockingMakeWriter {
    tx: SyncSender<Vec<u8>>,
}

pub struct NonBlockingWriter {
    tx: SyncSender<Vec<u8>>,
    buf: Vec<u8>,
}

pub struct LogGuard {
    tx: Option<SyncSender<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(Vec::new());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn non_blocking_writer<W: Write + Send + 'static>(mut sink: W, cap: usize) -> (NonBlockingMakeWriter, LogGuard) {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(cap.max(1));
    let handle = std::thread::Builder::new()
        .name("fucf-log".into())
        .spawn(move || {
            while let Ok(chunk) = rx.recv() {
                if chunk.is_empty() {
                    break;
                }
                let _ = sink.write_all(&chunk);
                while let Ok(more) = rx.try_recv() {
                    if more.is_empty() {
                        let _ = sink.flush();
                        return;
                    }
                    let _ = sink.write_all(&more);
                }
                let _ = sink.flush();
            }
        })
        .ok();
    (NonBlockingMakeWriter { tx: tx.clone() }, LogGuard { tx: Some(tx), handle })
}

pub fn init_stdout() -> LogGuard {
    let (maker, guard) = non_blocking_writer(io::stdout(), DEFAULT_LOG_CAP);
    tracing_subscriber::fmt().with_writer(maker).init();
    guard
}

impl<'a> MakeWriter<'a> for NonBlockingMakeWriter {
    type Writer = NonBlockingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        NonBlockingWriter { tx: self.tx.clone(), buf: Vec::with_capacity(256) }
    }
}

impl Write for NonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            match self.tx.try_send(chunk) {
                Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
        }
        Ok(())
    }
}

impl Drop for NonBlockingWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    struct StalledSink {
        gate: Arc<(Mutex<bool>, Condvar)>,
        written: Arc<AtomicUsize>,
    }

    impl Write for StalledSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let (lock, cv) = &*self.gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            self.written.fetch_add(buf.len(), Ordering::Relaxed);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn non_blocking_writer_drops_when_sink_stalls() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let written = Arc::new(AtomicUsize::new(0));
        let (maker, guard) = non_blocking_writer(StalledSink { gate: gate.clone(), written: written.clone() }, 8);

        let start = Instant::now();
        for i in 0..200 {
            let mut w = maker.make_writer();
            writeln!(w, "line {i}").unwrap();
            w.flush().unwrap();
        }
        assert!(start.elapsed() < Duration::from_millis(200), "writer blocked on stalled sink: {:?}", start.elapsed());

        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        drop(maker);
        drop(guard);
        assert!(written.load(Ordering::Relaxed) > 0);
    }
}
