fn main() {
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile == "debug");

    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(debug);
    if let Err(e) = slint_build::compile_with_config("ui/app.slint", config) {
        eprintln!("could not compile ui/app.slint: {e}");
        std::process::exit(1);
    }
}
