use std::time::Duration;

/// A WASM-compatible monotonic instant backed by `js_sys::Date::now()`.
///
/// `std::time::Instant` is not available on `wasm32-unknown-unknown`,
/// so this provides the subset of the API used by the upload / download
/// modules.
#[derive(Clone, Copy, Debug)]
pub struct Instant(f64);

impl Instant {
    pub fn now() -> Self {
        Instant(js_sys::Date::now())
    }

    pub fn elapsed(&self) -> Duration {
        Duration::from_millis((js_sys::Date::now() - self.0).max(0.0) as u64)
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_millis((self.0 - earlier.0).max(0.0) as u64)
    }
}

/// WASM-compatible async sleep using `setTimeout`.
pub async fn sleep(duration: Duration) {
    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
        let global = js_sys::global();
        let set_timeout: js_sys::Function =
            js_sys::Reflect::get(&global, &"setTimeout".into())
                .unwrap()
                .into();
        let _ = set_timeout.call2(
            &wasm_bindgen::JsValue::NULL,
            &resolve,
            &wasm_bindgen::JsValue::from_f64(duration.as_millis() as f64),
        );
    }))
    .await
    .unwrap();
}
