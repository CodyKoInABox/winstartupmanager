// Canonical Win Startup Manager logo shared by the UI and Windows resources.

/// Original user-supplied WSM logo, embedded into every application build.
pub const APP_LOGO_PNG: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/wsm_logo.png"));

/// Decode and resize the canonical logo into square RGBA pixels.
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    let side = size.max(1);
    let source = image::load_from_memory_with_format(APP_LOGO_PNG, image::ImageFormat::Png)
        .expect("embedded WSM logo must remain a valid PNG")
        .to_rgba8();
    image::imageops::resize(&source, side, side, image::imageops::FilterType::Lanczos3).into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_logo_decodes_and_resizes() {
        let icon = app_icon_rgba(32);
        assert_eq!(icon.len(), 32 * 32 * 4);
        assert!(icon.chunks_exact(4).any(|pixel| pixel[2] > pixel[0]));
        assert!(icon.chunks_exact(4).any(|pixel| pixel[0] > pixel[2]));
    }
}
