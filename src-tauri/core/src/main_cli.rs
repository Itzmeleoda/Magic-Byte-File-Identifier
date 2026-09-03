fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(fid_core::cli::run(&args));
}
