#![allow(unused)]
use nix::sys::signal::*;
use nix::sys::wait::*;
use nix::unistd::*;
use std::fmt;
use std::io::{self, Read};
use std::process;
use std::sync::atomic::AtomicBool;

pub enum InBuiltCmd {
    Quit,
    Jobs,
    Bg(i32),
    Fg(i32),
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

impl Shell {
    pub fn maybe_run_in_built_cmd(&self, cmd: &String) -> bool {
        match cmd.as_ref() {
            "quit" => {
                println!("quit");
                process::exit(0);
                true
            }
            "jobs" => {
                println!("jobs");
                self.print_jobs();
                true
            }
            _ => {
                println!("Need to run {}", cmd);
                false
            }
        }
    }

    fn print_jobs(&self) {
        println!("Jobs");
        for job in &self.jobs {
            println!("{}", job)
        }
    }
}

fn main() -> io::Result<()> {
    println!("Welcome to my shell");
    let shell = Shell {
        fg: None,
        jobs: vec![],
    };

    loop {
        // Parse command.
        let mut command = String::new();
        match io::stdin().read_line(&mut command) {
            Ok(_) => {
                // Remove trailing characters.
                command = command.trim().to_string();
            }
            Err(error) => println!("Error reading command"),
        }

        // Process the command.
        if (!shell.maybe_run_in_built_cmd(&command)) {
            // TODO: Fork and exec here.
            println!("Run process")
        }
    }
    Ok(())
}
