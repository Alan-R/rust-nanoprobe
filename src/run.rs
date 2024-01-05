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
/*
 * TODO: Need to figure out logging and/or tracing and implement them in this code
 */
use std::io;
#[cfg(target_family = "unix")]
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};
use std::str::FromStr;

#[cfg(target_family = "unix")]
use caps::{Capability, CapSet, CapsHashSet, securebits::set_keepcaps};
#[cfg(target_family = "unix")]
use libc::c_int;
#[cfg(target_family = "unix")]
use rlimit::{getrlimit, Resource, setrlimit};
#[cfg(target_family = "unix")]
use users::{get_group_by_name, get_user_by_name, gid_t, uid_t};
#[cfg(target_family = "unix")]

#[cfg(target_family = "unix")]
extern "C" {
    fn setuid(uid: uid_t) -> c_int;
    fn setgid(gid: gid_t) -> c_int;
}


/* UNIX Capability-related code */

#[cfg(target_family = "unix")]
/// Converts a list of UNIX capability names into a CapHashSet as needed by RestrictCaps below
/// These capability names can be non-canonical names as required by the caps crate.
/// # Arguments
/// * 'cap_list': a String iterator
/// # Examples:
fn cap_list_to_capset(cap_list: impl Iterator<Item=String>) -> Result<CapsHashSet, caps::errors::CapsError> {
    // Convert iterable Strings (possibly in non-canonical form) to a CapsHashSet
    let mut result_set = CapsHashSet::new();
    for cap_name in cap_list {
        let cap = Capability::from_str(&*caps::to_canonical(&*cap_name))?;
        result_set.insert(cap);
    }
    Ok(result_set)
}


#[cfg(target_family = "unix")]
/// A trait for restricting capabilities on **Command**s being executed.
pub trait RestrictCaps {
    fn restrict_caps<'a>(&mut self, cap_set: CapsHashSet) -> &mut Command;
}


#[cfg(target_family = "unix")]
impl RestrictCaps for Command {
    /// Restrict capabilities that a Command is run with
    /// This trait sets the capabilities in the Inheritable, Bounding, Ambient, and Effective sets.
    /// This code is scheduled to run between fork and exec of Commands, so that those commands
    /// are run with exactly and only the specified capabilities.
    /// This is done using Command.pre_exec().
    ///
    /// # Arguments
    /// * 'self' - Our self Command object
    /// * 'cap_set' - a CapsHashSet of the capabilities we want to have in our child process
    ///               possibly coming from cap_list_to_capset() above.
    fn restrict_caps<'a>(self: &mut Command, cap_set: CapsHashSet) -> &mut Command {
        unsafe {
            self.pre_exec(move || {
                // Remove unwanted capabilities
                // The ordering of items in 'capability_set' is important.
                for capability_set in [CapSet::Inheritable, CapSet::Bounding, CapSet::Ambient, CapSet::Effective] {
                    let current_set_caps = caps::read(None, capability_set);
                    match current_set_caps {
                        Err(_fail) => {
                            // We should log this...
                        }
                        Ok(current_set_caps) => {
                            // Add this capability
                            for cap in cap_set.iter() {
                                // TODO: Log failures
                                _ = caps::raise(None, capability_set, *cap);
                            }
                            for cap in current_set_caps {
                                // Remove any capability not specifically requested
                                if !cap_set.contains(&cap) {
                                    // TODO: Log failures
                                    _ = caps::drop(None, capability_set, cap);
                                }
                            }
                        }
                    }
                    println!("Final {:?} caps: {:?}", capability_set, caps::read(None, capability_set).unwrap());
                }
                Ok(())
            });
        }
        self
    }
}

/* UNIX SetUID-related code */
/// Trait for setting the User Id and group of our child **Command**
/// This trait also sets the **KEEPCAPS** attribute so that any capabilities which
/// have been set are preserved for the Command being run.
///
/// This code only exists because of how the Rust .uid() Command trait operates.
#[cfg(target_family = "unix")]
pub trait SetId {
    fn set_id_keep(&mut self, uid: uid_t, gid: gid_t) -> &mut Command;
}

#[cfg(target_family = "unix")]
impl SetId for Command {
    /// Implementation of code to set the user and group ids of our child Command
    /// This code is scheduled to run between fork and exec of Commands, so that those commands
    /// are run under the given user and group ids.
    /// This is done using Command.pre_exec().
    ///
    /// In case you're wondering why I don't use Command.uid() instead...
    /// As of this writing, Command.uid() runs before any of the scheduled *pre_exec* Command
    /// operations are performed. This means you can't set **KEEPCAPS** before changing
    /// user id. Without this implementation, you could change user ids, or you could preserve
    /// capabilities, but not both. Sigh...
    ///
    /// # Arguments
    /// * 'self' - Our self Command object
    /// * 'uid' - UNIX user id we want our Command to run as
    /// * 'gid' - UNIX group id we want our Command to run as
    fn set_id_keep(self: &mut Command, uid: uid_t, gid: gid_t) -> &mut Command {
        unsafe {
            self.pre_exec(move || {
                println!("set_id_keep: Effective caps {:?}:{:?} => {:?}", uid, gid, caps::read(None, CapSet::Effective).unwrap());
                // TODO: log failures
                _ = setgid(gid);
                _ = set_keepcaps(true); // Must do this before the call to setuid below.
                _ = setuid(uid);
                Ok(())
            }
            );
        }
        self
    }
}

/* UNIX resource limit-related code */

#[derive(Debug, Clone)]
/// A representation of resource limits as string-resource names and integer limits
/// See setrlimit(2) for UNIX (Linux) systems
pub struct StrResourceLimit {
    pub resource_type: String,
    pub soft_limit: u64,
    pub hard_limit: u64,
}

#[cfg(target_family = "unix")]
#[derive(Debug, Clone)]
/// A representation of resource limits as 'Resource' objects with integer limits
/// See setrlimit(2) for UNIX (Linux) systems
pub struct ResourceLimit {
    resource_type: Resource,
    soft_limit: u64,
    hard_limit: u64,
}

#[cfg(target_family = "unix")]
/// Converts a StrResourceLimit to a ResourceLimit
/// # Arguments
/// * 'str_limit' - the incoming StrResourceLimit object
/// # Examples:
fn str_resource_to_resource_limit<'a>(str_limit: &StrResourceLimit) -> io::Result<ResourceLimit> {
    match Resource::from_str(&*str_limit.resource_type) {
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput, format!("unknown resource type: {}", str_limit.resource_type),
        )),
        Ok(resource_type) => {
            if resource_type.is_supported() {
                if str_limit.soft_limit > str_limit.hard_limit {
                    Err(io::Error::new(io::ErrorKind::InvalidInput,
                                       format!("soft limit {} larger than hard limit {} for {}",
                                               str_limit.soft_limit, str_limit.hard_limit, str_limit.resource_type),
                    ))
                } else {
                    Ok(ResourceLimit { resource_type, soft_limit: str_limit.soft_limit, hard_limit: str_limit.hard_limit })
                }
            } else {
                Err(io::Error::new(io::ErrorKind::Unsupported,
                                   format!("unsupported resource type {}", str_limit.resource_type),
                ))
            }
        }
    }
}

#[cfg(target_family = "unix")]
/// Converts an iterable StrResourceLimit list  to a <Vec<ResourceLimit>>
/// # Arguments
/// * 'limit_list' - the incoming StrResourceLimit iterable list
/// # Examples:
fn str_resources_to_limits(limit_list: impl Iterator<Item=StrResourceLimit>) -> io::Result<Vec<ResourceLimit>> {
    let mut limits: Vec<ResourceLimit> = Vec::new();

    for str_limit in limit_list {
        match str_resource_to_resource_limit(&str_limit) {
            Ok(good_limit) => limits.push(good_limit),
            Err(oopsie) => { return Err(oopsie); }
        }
    }
    return Ok(limits);
}

#[cfg(target_family = "unix")]
/// Trait to set resource limits on our child Commands
/// This code is scheduled to run between fork and exec of Commands, so that those commands
/// are run with these resource limits.
/// This is done using Command.pre_exec().
/// Note that these resource limits should be set before dropping privileges, so that
/// it's possible to set resources to exceed the system's existing hard limit.
///
pub trait SetLimits {
    fn set_limits(&mut self, limits: Vec<ResourceLimit>) -> &mut Command;
}

#[cfg(target_family = "unix")]
impl SetLimits for Command {
    /// Function to set resource limits on our child Commands
    /// # Arguments
    /// * 'limit_list' - ResourceLimit Vector of resource limitations
    fn set_limits(self: &mut Command, limit_list: Vec<ResourceLimit>) -> &mut Command {
        unsafe {
            self.pre_exec(move || {
                for limit in limit_list.iter() {
                    println!("Limit name: {:?}", limit.resource_type);
                    let limit_check = getrlimit(limit.resource_type);
                    match limit_check {
                        Ok(current) => {
                            let mut soft = current.0;
                            let mut hard = current.1;
                            if limit.soft_limit != 0 {
                                soft = limit.soft_limit
                            }
                            if limit.hard_limit != 0 {
                                hard = limit.hard_limit
                            }
                            // TODO: log failures
                            _ = setrlimit(limit.resource_type, soft, hard)
                        }
                        Err(oops) => {
                            // TODO: log failures
                            println!("BAD: {:?}", oops);
                        }
                    }
                }
                Ok(())
            });
            self
        }
    }
}

/* Code to specify and run commands with capabilities and resource limits */

#[derive(Debug, Clone)]
/// A complete specification of a command and how to run it.
pub struct CommandSpecification {
    pub program_path: String,
    pub command_args: Vec<String>,
    pub capabilities: Vec<String>,
    pub resource_limits: Vec<StrResourceLimit>,
    pub userid: Option<String>,
    pub groupid: Option<String>,
}

impl CommandSpecification {
    /// Run the CommandSpecification:
    /// This includes
    /// - specifying the program pathname
    /// - specifying its arguments
    /// - specifying the capabilities to retain (default is to retain none) (UNIX only)
    /// - specifying any resource limits that we want to set on this command (UNIX only)
    /// - Optional user id to run it as (String) (UNIX only)
    /// - Optional group id to run it as (String) (UNIX only)
    pub fn run(&self) -> io::Result<Output> {
        let mut path_binding = Command::new(&*self.program_path);
        let mut command = path_binding.args(self.command_args.clone());
        if cfg!(target_family="unix") {
            // The order in which we do these operations is important:
            // 1. set user (and group) id (if present)
            // 2. set resource limits
            // 3. set/restrict capabilities.
            let limits = str_resources_to_limits(self.resource_limits.clone().into_iter())?;
            let requested_caps = cap_list_to_capset(self.capabilities.clone().into_iter()).unwrap();
            if self.userid.is_some() {
                let user_id = get_user_by_name(&self.userid.clone().unwrap());
                if user_id.is_some() {
                    let user_info = user_id.unwrap();
                    let mut gid = user_info.primary_group_id();
                    if self.groupid.is_some() {
                        let group_id = get_group_by_name(&self.groupid.as_ref().unwrap().clone());
                        if group_id.is_some() {
                            gid = group_id.unwrap().gid();
                        }
                    }
                    command = command.set_id_keep(user_info.uid(), gid);
                }
            } else {
                if self.groupid.is_some() {
                    let group_id = get_group_by_name(&self.groupid.as_ref().unwrap().clone());
                    if group_id.is_some() {
                        command = command.gid(group_id.unwrap().gid());
                    }
                }
            }
            command = command.set_limits(limits).restrict_caps(requested_caps);
        }
        command.output()
    }
}

#[cfg(test)]
// Should these be UNIX-only tests and have a different mod for non-UNIX specific tests?
mod tests {
    use super::*;
    #[cfg(target_family = "unix")]
    use users::{get_current_username, get_current_groupname};
    #[cfg(target_family = "unix")]
    #[test]
    fn test_cap_list_to_capset_success() {
        let cap_res = cap_list_to_capset(["chown".to_string(), "setuid".to_string()].into_iter());
        assert!(cap_res.is_ok());
        let mut caps = cap_res.unwrap();
        assert!(caps.contains(&Capability::CAP_CHOWN));
        assert!(caps.contains(&Capability::CAP_SETUID));
        caps.remove(&Capability::CAP_CHOWN);
        caps.remove(&Capability::CAP_SETUID);
        assert!(caps.is_empty());
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_cap_list_to_capset_fail() {
       let cap_res = cap_list_to_capset(["chown".to_string(), "setfoo".to_string()].into_iter());
        assert!(cap_res.is_err());
        let err_msg =  cap_res.expect_err("REASON").to_string();
        assert_eq!(err_msg, "caps error: invalid capability: CAP_SETFOO");
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resource_to_resource_limit_success() {
        let s_limit = StrResourceLimit {
            resource_type: "RLIMIT_CPU".to_string(),
            soft_limit: 42,
            hard_limit: 2*42,
        };
        let ok_limit = str_resource_to_resource_limit(&s_limit);
        assert!(ok_limit.is_ok());
        let limit = ok_limit.unwrap();
        assert_eq!(limit.soft_limit, 42);
        assert_eq!(limit.hard_limit, 42*2);
        assert_eq!(limit.resource_type, Resource::CPU);
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resource_to_resource_limit_fail_bad_type() {
        let s_limit = StrResourceLimit {
            resource_type: "RLIMIT_CUP".to_string(),
            soft_limit: 42,
            hard_limit: 2*42,
        };
        let bad_limit = str_resource_to_resource_limit(&s_limit);
        assert!(bad_limit.is_err());
        let err_msg =  bad_limit.expect_err("REASON").to_string();
        assert_eq!(err_msg, "unknown resource type: RLIMIT_CUP")
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resource_to_resource_limit_fail_bad_limits() {
        let s_limit = StrResourceLimit {
            resource_type: "RLIMIT_CPU".to_string(),
            soft_limit: 2*42,
            hard_limit: 42,
        };
        let bad_limit = str_resource_to_resource_limit(&s_limit);
        assert!(bad_limit.is_err());
        let err_msg =  bad_limit.expect_err("REASON").to_string();
        assert_eq!(err_msg, "soft limit 84 larger than hard limit 42 for RLIMIT_CPU")
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resources_to_limits_success() {
        let limits = [
            StrResourceLimit {
                resource_type: "RLIMIT_CPU".to_string(),
                hard_limit: 2*42,
                soft_limit: 42,
           },
            StrResourceLimit {
                resource_type: "RLIMIT_NOFILE".to_string(),
                hard_limit: 2*42*42,
                soft_limit: 42*42,
           }
        ].to_vec();

        let ok_limit_vec = str_resources_to_limits(limits.into_iter());
        assert!(ok_limit_vec.is_ok());
        let limit_vec = ok_limit_vec.unwrap();
        assert_eq!(limit_vec.len(), 2);
        assert_eq!(limit_vec[0].soft_limit, 42);
        assert_eq!(limit_vec[0].hard_limit, 42*2);
        assert_eq!(limit_vec[1].resource_type, Resource::NOFILE);
        assert_eq!(limit_vec[1].soft_limit, 42*42);
        assert_eq!(limit_vec[1].hard_limit, 42*42*2);
        assert_eq!(limit_vec[0].resource_type, Resource::CPU);
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resources_to_limits_fail_invalid_resource() {
        let limits = [
            StrResourceLimit {
                resource_type: "RLIMIT_CPU".to_string(),
                soft_limit: 42,
                hard_limit: 2*42,
            },
            StrResourceLimit {
                resource_type: "RLIMIT_N0FILE".to_string(),
                soft_limit: 42*42,
                hard_limit: 2*42*42,
            }
        ].to_vec();

        let err_limit_vec = str_resources_to_limits(limits.into_iter());
        assert!(err_limit_vec.is_err());
        let err_msg =  err_limit_vec.expect_err("REASON").to_string();
        assert_eq!(err_msg, "unknown resource type: RLIMIT_N0FILE")
    }
    #[cfg(target_family = "unix")]
    #[test]
    fn test_str_resources_to_limits_fail_invalid_limits() {
        let limits = [
            StrResourceLimit {
                resource_type: "RLIMIT_CPU".to_string(),
                soft_limit: 2*42,
                hard_limit: 42,
            },
            StrResourceLimit {
                resource_type: "RLIMIT_N0FILE".to_string(),
                soft_limit: 42*42,
                hard_limit: 2*42*42,
            }
        ].to_vec();

        let err_limit_vec = str_resources_to_limits(limits.into_iter());
        assert!(err_limit_vec.is_err());
        let err_msg =  err_limit_vec.expect_err("REASON").to_string();
        assert_eq!(err_msg, "soft limit 84 larger than hard limit 42 for RLIMIT_CPU")
    }
    #[test]
    /// This test exercises almost all the features at once. The exception is the setgid only path in the code.
    /// Coverage doesn't include things done in the child process.
    fn test_run_command_basic() {
        let path: &str;
        let args: Vec<String>;
        if cfg!(target_family = "unix") {
            path = "/bin/echo";
            args = ["Hello, world!".to_string()].to_vec();
        }else{
            path = "cmd";
            args = ["/C".to_string(), "echo Hello, world!".to_string()].to_vec();
        }
        let limits = [
            StrResourceLimit {
                resource_type: "RLIMIT_CPU".to_string(),
                hard_limit: 2*42,
                soft_limit: 42,
            }
        ].to_vec();
        let spec = CommandSpecification {
            program_path: path.to_string(),
            command_args: args,
            capabilities: ["chown".to_string()].to_vec(),
            resource_limits: limits,
            userid:  {
                if cfg!(target_family = "unix") {
                    Some(get_current_username().unwrap().to_string_lossy().to_string())
                } else {
                    None
                }
            },
            groupid:  {
                if cfg!(target_family = "unix") {
                    Some(get_current_groupname().unwrap().to_string_lossy().to_string())
                } else {
                    None
                }
            },
        };
        let result = spec.run();
        assert!(result.is_ok());
        let output = result.unwrap();
        let hello = std::str::from_utf8(&output.stdout);
        let hello_err = std::str::from_utf8(&output.stderr);
        assert!(hello.is_ok());
        assert!(hello_err.is_ok());
        assert_eq!(hello.unwrap().trim_end(), "Hello, world!");
        assert_eq!(hello_err.unwrap().trim_end(), "");
        assert!(output.status.success())
    }
}
