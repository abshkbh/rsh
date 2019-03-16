#![allow(unused)]
use nix::sys::signal::*;
use nix::sys::wait::*;
use nix::unistd::*;
use std::fmt;
use std::sync::atomic::AtomicBool;
use std::io::{self, Read};

pub enum InBuiltCmd {
    Quit,
    Jobs,
    Bg(i32),
    Fg(i33),
    Kill(i32),
}

enum JobState {
    Foreground,
    Background,
    Stopped,
}

struct Job {
    // Pid of this job.
    pid: Pid,

    // Entire cmd line used to invoke the jobs.
    cmd_line: String,

    // Current state of the job.
    state: JobState,
}

impl fmt::Display for Job {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state_display = if let JobState::Stopped = self.state {
            String::from("stopped")
        } else {
            String::from("running")
        };

        write!(f, "+ {} {}", state_display, self.cmd_line).expect("Failed to display a job");
        Ok(())
    }
}

pub struct Shell {
    // Pid of the foreground process. Should be None if no foreground process running.
    fg: Option<Pid>,

    jobs: Vec<Job>,
}

fn main() -> io::Result<()> {
    println!("Welcome to my shell");

    loop {
        let mut command = String::new();
        match io::stdin().read_line(&mut command) {
            Ok(_) => println!("Command: {}", command),
            Err(error) => println!("Error reading command"),
        }
    }
    Ok(())
}
