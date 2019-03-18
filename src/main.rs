#![allow(unused)]
use nix::sys::signal::*;
use nix::sys::wait::*;
use nix::unistd::*;
use nix::Error;
use std::fmt;
use std::io::{self, Read};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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

unsafe fn install_signal_handler(signum: Signal, sig_handler: SigHandler) {
    let mut sigset = SigSet::empty();
    // Restart syscalls and block signals of the same type if this signal is being processed.
    let mut sa_flags = SaFlags::empty();
    sa_flags.insert(SaFlags::SA_RESTART);
    let sig_action = SigAction::new(sig_handler, sa_flags, SigSet::empty());
    // This is safe to do as |sig_action| is in the stack initialized before this.
    sigaction(signum, &sig_action).expect("Failed to install handler for signal");
}

fn block_signal(sigset: Option<&SigSet>) {
    match sigprocmask(SigmaskHow::SIG_BLOCK, sigset, None) {
        Ok(_) => (),
        _ => panic!("Failed to block signal"),
    }
}

#[no_mangle]
extern "C" fn sigint_handler(arg: libc::c_int) {
    println!("SIGINT");
}

#[no_mangle]
extern "C" fn sigchld_handler(arg: libc::c_int) {
    println!("SIGCHLD");
}

#[no_mangle]
extern "C" fn sigtstp_handler(arg: libc::c_int) {
    println!("SIGSTP");
}

fn main() -> io::Result<()> {
    println!("Welcome to my shell");
    let shell = Shell {
        fg: None,
        jobs: vec![],
    };

    // Install the handlers for SIGINT, SIGCHLD, SIGTSTP.
    unsafe {
        install_signal_handler(Signal::SIGINT, SigHandler::Handler(sigint_handler));
        install_signal_handler(Signal::SIGCHLD, SigHandler::Handler(sigchld_handler));
        install_signal_handler(Signal::SIGTSTP, SigHandler::Handler(sigtstp_handler));
    }

    // Block SIGINT, SIGCHLD, SIGTSTP till command is being parsed.
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGINT);
    sigset.add(Signal::SIGCHLD);
    sigset.add(Signal::SIGTSTP);
    block_signal(Some(&sigset));

    // Spawn a thread to handle IO. This is done to keep the main thread free to handle signals.
    let (cmd_line_tx, cmd_line_rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            let mut command = String::new();
            match io::stdin().read_line(&mut command) {
                Ok(_) => {
                    // Remove trailing characters.
                    command = command.trim().to_string();
                    cmd_line_tx.send(command).expect("Failed to send command");
                }

                Err(error) => println!("Error reading command"),
            }
        }
    });

    // Loop to process events after periodic sleep.
    loop {
        // Check and process command line.
        match cmd_line_rx.try_recv() {
            Ok(command) => {
                // Process the command.
                if (!shell.maybe_run_in_built_cmd(&command)) {
                    // TODO: Fork and exec here.
                    println!("Run process")
                }
            }

            Err(e) => match e {
                mpsc::TryRecvError::Disconnected => panic!("IO thread should not be killed"),
                _ => (),
            },
        }

        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}
