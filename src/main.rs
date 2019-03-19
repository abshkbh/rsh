#![allow(unused)]
use nix::sys::signal::*;
use nix::sys::signalfd::*;
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
    pub fn run_cmd(&mut self, cmd: String) {
        // Process the command.
        if (!Self::maybe_run_in_built_cmd(self, &cmd)) {
            Self::fork_and_run_cmd(self, cmd);
        }
    }

    pub fn maybe_run_in_built_cmd(&mut self, cmd: &String) -> bool {
        println!("Run inbuilt cmd {}", cmd);
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

    pub fn fork_and_run_cmd(&mut self, cmd: String) {
        println!("Run new process");
        let result = fork();
        let bg_process = cmd.ends_with("&");
        println!("Is Bg Process: {}", bg_process);
        match result {
            Ok(ForkResult::Parent { child }) => {
                println!("In the parent child pid {}", child);
                self.fg = Some(child);
                self.jobs.push(Job {
                    pid: child,
                    cmd_line: cmd,
                    state: JobState::Foreground,
                });

                match wait() {
                    // TODO: More specific matching for T.
                    Ok(t) => println!("Child exited"),
                    Err(_) => println!("Child reaped"),
                }
                println!("After child exit");
            }

            Ok(ForkResult::Child) => {
                println!("In the child");
                // Unblock all signals in the child.
                let sigset = SigSet::all();
                unblock_signal(Some(&sigset));
                // TODO: Call execvp here.
            }

            Err(_) => println!("Fork failed"),
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

fn unblock_signal(sigset: Option<&SigSet>) {
    match sigprocmask(SigmaskHow::SIG_UNBLOCK, sigset, None) {
        Ok(_) => (),
        _ => panic!("Failed to block signal"),
    }
}

fn main() -> io::Result<()> {
    println!("Welcome to my shell");
    let mut shell = Shell {
        fg: None,
        jobs: vec![],
    };

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
    
    // Set up signal fd to listen to SIGINT, SIGCHLD and SIGTSTP. This is done
    // so that these signals can be handled on the main thread in a race free
    // manner. These signals also need to be blocked first to prevent their
    // default actions.
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGINT);
    sigset.add(Signal::SIGCHLD);
    sigset.add(Signal::SIGTSTP);
    block_signal(Some(&sigset));
    // Set singal fd to be non blocking in order to not block the main shell
    // prompt. Also, close it on exec as it won't be needed for child processes
    // forked by the shell.
    let mut sfd_flags = SfdFlags::empty();
    sfd_flags.set(SfdFlags::SFD_NONBLOCK, true);
    sfd_flags.set(SfdFlags::SFD_CLOEXEC, true);
    let mut sfd = SignalFd::with_flags(&sigset, sfd_flags).unwrap();

    // Loop to process events after periodic sleep.
    loop {
        // Check and process command line in a non-blocking way.
        match cmd_line_rx.try_recv() {
            Ok(cmd) => shell.run_cmd(cmd),

            Err(e) => match e {
                mpsc::TryRecvError::Disconnected => panic!("IO thread should not be killed"),
                _ => (),
            },
        }

        // Check and process signals in a non-blocking way.
        match sfd.read_signal() {
            // Handle signal.
            Ok(Some(sig)) => println!("Caught signal {}", sig.ssi_signo),
            // No signal occured.
            Ok(None) => (),
            // Some error happened.
            Err(_) => (),
        }

        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}
