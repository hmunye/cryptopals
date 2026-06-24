use std::ffi::{c_int, c_uint, c_void};

unsafe extern "C" {
    // ssize_t getrandom(size_t size;
    //                   void buf[size], size_t size, unsigned int flags);
    pub fn getrandom(buf: *mut c_void, size: usize, flags: c_uint) -> isize;

    // int rand(void);
    pub fn rand() -> c_int;
    // void srand(unsigned int seed);
    pub fn srand(seed: c_uint);
}
