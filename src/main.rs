#![allow(unused)]
use nix::sys::epoll::*;
use nix::sys::signal::*;
use nix::sys::signalfd::SignalFd;
use nix::sys::signalfd::*;
use nix::sys::wait::*;
use nix::unistd::*;
use nix::Error;
use std::ffi::CString;
use std::fmt;
use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
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
    pub fn run_cmd(&mut self, cmd: String, is_fg: bool) {
        // Process the command.
        if (!Self::maybe_run_in_built_cmd(self, &cmd)) {
            Self::fork_and_run_cmd(self, cmd, is_fg);
        }
    }

    pub fn maybe_run_in_built_cmd(&mut self, cmd: &String) -> bool {
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

    pub fn fork_and_run_cmd(&mut self, cmd: String, is_fg: bool) {
        let result = fork();
        match result {
            Ok(ForkResult::Parent { child }) => {
                println!("In the Parent - Child's pid {}", child);
                self.fg = Some(child);
                let job_state = if (is_fg) {
                    JobState::Foreground
                } else {
                    JobState::Background
                };
                self.jobs.push(Job {
                    pid: child,
                    cmd_line: cmd,
                    state: job_state,
                });
            }

            Ok(ForkResult::Child) => {
                println!("In the child {}", cmd);

                // Set new process group for the child. The gid will be the pid
                // of the new process.
                match nix::unistd::setpgid(
                    nix::unistd::Pid::from_raw(0),
                    nix::unistd::Pid::from_raw(0),
                ) {
                    Err(e) => {
                        println!("Failed to setpgid error: {}", e);
                        process::exit(-1);
                        return;
                    }
                    _ => (),
                }

                // Unblock all signals in the child.
                let mut sigset = SigSet::empty();
                sigset.add(Signal::SIGINT);
                sigset.add(Signal::SIGCHLD);
                sigset.add(Signal::SIGTSTP);
                unblock_signal(Some(&sigset));

                let filename = if let Ok(filename) = CString::new(cmd) {
                    filename
                } else {
                    println!("No command given");
                    process::exit(-1);
                    return;
                };

                // Parse args.
                let mut args: [CString; 0] = [];
                match nix::unistd::execvp(&filename, &args) {
                    Err(e) => {
                        // Exit the forked process if exec-ing command has failed.
                        println!("Failed to exec {}", e);
                        process::exit(-1);
                    }
                    _ => (),
                }
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

fn perform_epoll_op(epfd: RawFd, op: EpollOp, fd: RawFd) {
    // Event doesn't matter if op maps to EPOLL_CTL_DEL
    let mut epoll_event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLWAKEUP, fd as u64);
    epoll_ctl(epfd, op, fd, &mut epoll_event).unwrap();
}

fn main() -> io::Result<()> {
    let mut shell = Shell {
        fg: None,
        jobs: vec![],
    };

    // Set up signal fd to listen to SIGINT, SIGCHLD and SIGTSTP. This is done
    // so that these signals can be handled on the main thread in a race free
    // manner. These signals also need to be blocked first to prevent their
    // default actions.
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGINT);
    sigset.add(Signal::SIGCHLD);
    sigset.add(Signal::SIGTSTP);
    block_signal(Some(&sigset));

    // Set signal fd to be non blocking in order to not block the main shell
    // prompt. Also, close it on exec as it won't be needed for child processes
    // forked by the shell.
    let mut sfd_flags = SfdFlags::empty();
    sfd_flags.set(SfdFlags::SFD_NONBLOCK, true);
    sfd_flags.set(SfdFlags::SFD_CLOEXEC, true);
    let mut sfd = SignalFd::with_flags(&sigset, sfd_flags).unwrap();
    println!("Sfd val: {}", sfd.as_raw_fd());

    // Create epoll fd to monitor stdin for commands and signal fd for signals.
    let epoll_fd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    perform_epoll_op(epoll_fd, EpollOp::EpollCtlAdd, libc::STDIN_FILENO);
    perform_epoll_op(epoll_fd, EpollOp::EpollCtlAdd, sfd.as_raw_fd());

    println!("Welcome to my shell");
    loop {
        let mut events: [EpollEvent; 2] = [EpollEvent::empty(), EpollEvent::empty()];
        let num_events = epoll_wait(epoll_fd, &mut events, -1).unwrap();
        for i in 0..num_events {
            let fd = events[i].data();
            let stdin_fd = libc::STDIN_FILENO as u64;
            let sfd_u64 = sfd.as_raw_fd() as u64;
            println!("Got event on: {} sfd: {} stdin: {}", fd, sfd_u64, stdin_fd);
            if (fd == sfd_u64) {
                println!("In signal handling");
                match sfd.read_signal() {
                    // Handle signal.
                    Ok(Some(sig)) => println!("Caught signal {}", sig.ssi_signo),
                    // No signal occured.
                    Ok(None) => (),
                    // Some error happened.
                    Err(e) => println!("Error reading signal: {}", e),
                }
            } else if (fd == stdin_fd) {
                println!("In cmd handling");
                let mut cmd = String::new();
                match io::stdin().read_line(&mut cmd) {
                    Ok(_) => {
                        // Remove trailing characters.
                        cmd = cmd.trim().to_string();
                        // If a foreground process will be run then remove
                        // stdin from the monitored fds. This is required
                        // becasuse the shell should not eat the input for
                        // the process as well as the shell has to wait
                        // till the foregorund process finishes.
                        if (!cmd.is_empty()) {
                            println!("New cmd: {}", cmd);
                            let is_fg = !cmd.ends_with("&");
                            if (is_fg) {
                                perform_epoll_op(
                                    epoll_fd,
                                    EpollOp::EpollCtlDel,
                                    libc::STDIN_FILENO,
                                );
                            }
                            shell.run_cmd(cmd, is_fg);
                        }
                    }

                    Err(e) => println!("Error reading cmd: {}", e),
                }
            } else {
                println!("Unknown event on: {}", fd);
            }
        }
    }

    /*
    // Loop to process events after periodic sleep.
    let mut wait_for_new_cmd = true;
    loop {
        if wait_for_new_cmd {
            let mut cmd = String::new();
            match io::stdin().read_line(&mut cmd) {
                Ok(_) => {
                    // Remove trailing characters.
                    cmd = cmd.trim().to_string();
                    // Blocks if a foreground process is run.
                    if (!cmd.is_empty()) {
                        println!("New cmd: {}", cmd);
                        shell.run_cmd(cmd);
                    }
                }

                Err(error) => println!("Error reading cmd"),
            }
        }

        println!("Waiting to reap children");
        let mut flags = WaitPidFlag::empty();
        flags.set(WaitPidFlag::WNOHANG, true);
        flags.set(WaitPidFlag::WUNTRACED, true);
        match waitpid(None, Some(flags)) {
            Ok(t) => match t {
                WaitStatus::Exited(pid, status) => {
                    wait_for_new_cmd = true;
                    println!("{} exited with {}", pid, status);
                }
                WaitStatus::Stopped(pid, signal) => {
                    wait_for_new_cmd = true;
                    println!("{} stopped due to signal {}", pid, signal)
                }
                WaitStatus::Signaled(pid, signal, is_coredump) => {
                    wait_for_new_cmd = true;
                    println!(
                        "{} signaled due to signal {} coredumped {}",
                        pid, signal, is_coredump
                    );
                }
                WaitStatus::Continued(pid) => println!("{} continued", pid),
                WaitStatus::StillAlive => {
                    wait_for_new_cmd = false;
                    println!("Children still alive");
                }
                _ => println!("Ptrace event"),
            },

            Err(e) => println!("Wait error {}", e),
        }

        println!("Waiting for signals");
        // Check and process signals in a non-blocking way.
        match sfd.read_signal() {
            // Handle signal.
            Ok(Some(sig)) => println!("Caught signal {}", sig.ssi_signo),
            // No signal occured.
            Ok(None) => (),
            // Some error happened.
            Err(_) => (),
        }

        thread::sleep(Duration::from_secs(1));
    }
    */

    Ok(())
}
