#[macro_export]
macro_rules! printdev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            let tag = module_path!().rsplit("::").next().unwrap_or("KF");
            println!("[KF:{}] {}", tag.to_uppercase(), format!($($arg)*));
        }
    };
}