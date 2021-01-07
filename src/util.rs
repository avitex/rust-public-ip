use once_cell::sync::OnceCell;

pub use tokio::runtime::Runtime as TokioRuntime;

// This runtime is initialized only when used.
pub fn tokio_runtime() -> &'static TokioRuntime {
    static RT: OnceCell<TokioRuntime> = OnceCell::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .enable_io()
            .build()
            .expect("failed to start tokio runtime")
    })
}
