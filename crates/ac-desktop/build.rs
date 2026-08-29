fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    if let Err(e) = slint_build::compile_with_config("ui/app.slint", config) {
        // Not `expect`: the workspace denies `expect_used`, and a panic here prints worse.
        eprintln!("could not compile ui/app.slint: {e}");
        std::process::exit(1);
    }
}
