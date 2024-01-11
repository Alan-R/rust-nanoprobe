/*
 *  This module provides for controlled execution of commands for Assimilation nanoprobes.
 *
 *  Because many of the things which nanoprobes need to do require root privileges, this code runs commands
 *  in very controlled environments, where each script gets only the privileges it needs to do its job.
 *  In addition, resource limits (either higher or lower) can be specified. The most obvious one is
 *  to limit CPU consumption to avoid runaway child processes.
 *
 *  I think this should also set up each child as its own process group, so that each child and its children
 *  can be killed gracefully.
 *
 */
use crate::run::{CommandSpecification, StrResourceLimit};
mod addresses;
pub mod run;
pub mod tlv;

fn main() {
    // let requested_cap_list = ["chown", "setuid"];
    let requested_limits = [
        StrResourceLimit {
            resource_type: "RLIMIT_CPU".to_string(),
            soft_limit: 42,
            hard_limit: 42 * 2,
        },
        StrResourceLimit {
            resource_type: "RLIMIT_NOFILE".to_string(),
            soft_limit: 42 * 42,
            hard_limit: 2 * 42 * 42,
        },
    ]
    .to_vec();

    let spec = CommandSpecification {
        program_path: "/bin/sh".to_string(),
        command_args: [
            "-c".to_string(),
            "-x".to_string(),
            "ulimit -a; id; /usr/sbin/capsh --print".to_string(),
        ]
        .to_vec(),
        capabilities: ["chown".to_string(), "setuid".to_string()].to_vec(),
        resource_limits: requested_limits,
        userid: Some("nobody".to_string()),
        // userid: None,
        groupid: None,
    };

    let output = spec.run();

    match output {
        Err(oopsie) => {
            println!("OOPSIE: {:?}", oopsie);
        }
        Ok(out) => {
            let hello = std::str::from_utf8(&out.stdout);
            let hello_err = std::str::from_utf8(&out.stderr);
            println!("{}, STDOUT:\n{:}", out.status, hello.unwrap());
            println!("STDERR: {:?}", hello_err);
        }
    }
} // main
