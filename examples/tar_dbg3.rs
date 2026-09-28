use ctf_tools::bytesource::ByteSource;
use ctf_tools::engine::{EngineLimits, RecursiveEngine};

fn main() {
    // Direct handler call, no engine — is the child there?
    let mut tar = Vec::new();
    let mut header = [0u8; 512];
    header[..9].copy_from_slice(b"good.txt\0");
    header[124..136].copy_from_slice(b"00000000010\0");
    header[156] = b'0';
    header[257..262].copy_from_slice(b"ustar");
    tar.extend_from_slice(&header);
    tar.extend_from_slice(b"GOODDATA");
    tar.resize(tar.len() + 504, 0);
    tar.extend(std::iter::repeat(0u8).take(1024));
    let mut bad = [0u8; 512];
    bad[..4].copy_from_slice(b"cut\0");
    bad[124..136].copy_from_slice(b"00000000012\0");
    bad[156] = b'0';
    bad[257..262].copy_from_slice(b"ustar");
    tar.extend_from_slice(&bad);
    tar.extend_from_slice(b"CUT1");
    tar.truncate(tar.len() - 1024);
    let src = ByteSource::from_vec(tar.clone());
    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);
    for a in &g.artifacts {
        if a.format == "tar" {
            for (_, c) in g.children(a.id) {
                println!("tar child: {:?} size={}", c.label, c.size);
            }
        }
    }
}
