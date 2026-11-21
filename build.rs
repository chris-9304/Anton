fn main() {
    #[cfg(feature = "desktop")]
    slint_build::compile("ui/appwindow.slint").expect("compile desktop UI");
}
