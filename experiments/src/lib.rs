extern crate libc;
use libc::{c_char, c_int, c_void, size_t};
extern "C" {
    pub fn print_n2n_version();
    pub fn quick_edge_start(secret: *const c_char, supernode_addr: *const c_char, community_name: *const c_char,
                            edge_addr: *const c_char, mac: *const c_char) -> c_int;
    pub fn quick_super_node_start(port: c_int) -> c_int;
}