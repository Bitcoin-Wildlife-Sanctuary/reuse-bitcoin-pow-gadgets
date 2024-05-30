pub(crate) mod treepp {
    pub use bitcoin_script::{define_pushable, script};
    #[cfg(test)]
    pub use bitcoin_scriptexec::{convert_to_witness, execute_script, execute_script_with_witness};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

pub mod structures;

pub mod spv;

pub mod utils;

#[macro_export]
macro_rules! consensus_encode {
    ($x: expr) => {{
        let mut bytes = vec![];
        $x.consensus_encode(&mut bytes).unwrap();
        bytes
    }};
}
