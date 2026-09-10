fn main() {
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile == "debug");

    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(debug);
    if let Err(e) = slint_build::compile_with_config("ui/app.slint", config) {
        eprintln!("could not compile ui/app.slint: {e}");
        std::process::exit(1);
    }

    // The video tests look for the vendored ffmpeg, which is named after the target it was
    // fetched for. Nothing but those tests reads this.
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=TEST_TARGET={target}");

    place_ffmpeg(&target);
}

/// Put the vendored ffmpeg where the binary will look for it: beside itself.
///
/// The installer does this when it packages a release. Without it here, a build run straight
/// out of the target directory finds no ffmpeg and falls back to a placeholder for every
/// video — which looks exactly like a decoding bug and is not one.
fn place_ffmpeg(target: &str) {
    if target.is_empty() {
        return;
    }
    let manifest = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => return,
    };
    let from = manifest.join("vendor").join(format!("ac-ffmpeg-{target}"));
    println!("cargo:rerun-if-changed={}", from.display());

    if !from.is_file() {
        // Normal on a platform nobody has vendored for yet: videos get a placeholder and
        // everything else works.
        println!(
            "cargo:warning=no vendored ffmpeg for {target}; video previews will be placeholders"
        );
        return;
    }

    // `OUT_DIR` is `<target>/<profile>/build/<pkg>-<hash>/out`, and the binary lands three
    // levels above it. There is no cargo variable that names that directory outright.
    let Some(beside) = std::env::var("OUT_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .and_then(|out| Some(out.ancestors().nth(3)?.to_path_buf()))
    else {
        return;
    };

    let to = beside.join(exe_name("ac-ffmpeg"));
    if let Err(e) = copy_tool(&from, &to) {
        println!("cargo:warning=could not put ffmpeg beside the binary: {e}");
    }
}

fn exe_name(stem: &str) -> String {
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("windows") => format!("{stem}.exe"),
        _ => stem.to_owned(),
    }
}

/// Copy it and keep it runnable. Skipped when the copy is already current, because this runs
/// on every build and the binary is tens of megabytes.
fn copy_tool(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    let fresh = std::fs::metadata(from)?;
    if let Ok(have) = std::fs::metadata(to)
        && have.len() == fresh.len()
    {
        return Ok(());
    }

    std::fs::copy(from, to)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
