use nix::sys::epoll::*;
use nix::sys::signal::*;
use nix::sys::signalfd::SignalFd;
use nix::sys::signalfd::*;
use nix::sys::wait::*;
use nix::unistd::*;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::process;

pub enum InBuiltCmd {
    Quit,
    Jobs,
    Bg(i32),
    Fg(i32),
    Kill(i32),
}

#[derive(PartialEq)]
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

    quit_initiated: bool,
}

impl Shell {
    pub fn run_in_built_cmd(&mut self, cmd: &str) {
        if cmd.starts_with("quit") {
            println!("quit");
            // Tell all jobs that the controlling terminal is dying before
            // exiting. The shell would exit after processes are reaped in
            // |reap_children|.
            self.send_signal_to_all_jobs(Signal::SIGKILL);
            self.quit_initiated = true;
        } else if cmd.starts_with("jobs") {
            println!("jobs");
            self.print_jobs();
        } else if cmd.starts_with("bg") {
            println!("bg");
            let args: Vec<&str> = cmd.split_whitespace().collect();
            // Do nothing if exact number of args aren't provided to "bg".
            if args.len() != 2 {
                println!("Args len mismatch {}", args.len());
                return;
            }

            // Extract job id from args and send it a SIGCONT.
            if args[1].starts_with("%") {
                // TODO: Handle unwrap here.
                let mut j_id =
                    i32::from_str_radix(args[1].trim_start_matches("%"), 10).unwrap() as usize;

                if j_id == 0 {
                    return;
                }

                j_id = j_id - 1;
                if j_id < self.jobs.len() {
                    println!("Job {} Pid {} sent SIGCONT", j_id, self.jobs[j_id].pid);
                    kill(
                        Pid::from_raw(-self.jobs[j_id].pid.as_raw()),
                        signal::SIGCONT,
                    )
                    .unwrap();
                }
            } else {
                let pid = i32::from_str_radix(args[1].trim_start_matches("%"), 10).unwrap();
                if let Some(j_id) = self.pid_to_jid(Pid::from_raw(pid)) {
                    if j_id < self.jobs.len() {
                        println!("Job {} Pid {} sent SIGCONT", j_id, pid);
                        kill(Pid::from_raw(-pid), signal::SIGCONT).unwrap();
                    }
                }
            }
        } else if cmd.starts_with("fg") {
            println!("fg");
        }
    }

    pub fn fork_and_run_cmd(&mut self, cmd: String, is_fg: bool) -> bool {
        let result = fork();
        match result {
            Ok(ForkResult::Parent { child }) => {
                println!("In the Parent - Child's pid {}", child);
                self.fg = Some(child);
                let job_state = if is_fg {
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
                };

                // Parse args.
                let args: [CString; 0] = [];
                match nix::unistd::execvp(&filename, &args) {
                    Err(e) => {
                        // Exit the forked process if exec-ing command has failed.
                        println!("Failed to exec {}", e);
                        process::exit(-1);
                    }
                    _ => (),
                }
            }

            Err(_) => {
                println!("Fork failed");
                return false;
            }
        }

        true
    }

    fn print_jobs(&self) {
        println!("Jobs");
        for job in &self.jobs {
            println!("{}", job)
        }
    }

    fn send_signal_to_fg(&self, sig: Signal) {
        // Send signal to the foreground process group if it exists.
        if let Some(pid) = self.fg {
            kill(Pid::from_raw(-pid.as_raw()), sig).unwrap();
        }
    }

    fn send_signal_to_all_jobs(&self, sig: Signal) {
        for job in &self.jobs {
            kill(Pid::from_raw(-job.pid.as_raw()), sig).unwrap();
        }
    }

    // Reaps children that are ready for reaping. Returns true iff foreground
    // process is reaped.
    fn reap_children(&mut self) -> bool {
        let mut result = false;
        // First reap foreground process and then all other children.
        if let Some(pid) = self.fg {
            println!("Wait for foreground process");
            result = self.wait_for_children(Some(pid));
            if result {
                self.fg = None;
            }
        }

        // TODO: Iterate and wait for all remaining processes.
        println!("Wait for remaining processes");
        self.wait_for_children(None);

        // If this is a reap after a "quit" was issued then exit the terminal.
        if self.quit_initiated {
            process::exit(0);
        }

        result
    }

    fn wait_for_children(&mut self, pid: Option<Pid>) -> bool {
        let mut result = false;
        let mut flags = WaitPidFlag::empty();
        flags.set(WaitPidFlag::WNOHANG, true);
        flags.set(WaitPidFlag::WUNTRACED, true);
        flags.set(WaitPidFlag::WCONTINUED, true);
        match waitpid(pid, Some(flags)) {
            Ok(t) => match t {
                // Reap process and remove it from internal list of jobs.
                WaitStatus::Exited(pid, status) => {
                    result = true;
                    println!("{} exited with {}", pid, status);
                    self.remove_pid_from_jobs(pid);
                }

                // Change state of the job to stopped.
                WaitStatus::Stopped(pid, signal) => {
                    result = true;
                    let job_id = self.pid_to_jid(pid);
                    if let Some(jid) = job_id {
                        println!("Job [{}] ({}) stopped by signal {}", jid, pid, signal);
                        self.jobs[jid].state = JobState::Stopped;
                    }
                }

                // Reap process and remove it from internal list of jobs.
                WaitStatus::Signaled(pid, signal, is_coredump) => {
                    println!(
                        "{} signaled due to signal {} coredumped {}",
                        pid, signal, is_coredump
                    );
                    let jid = self.pid_to_jid(pid);
                    if let Some(job_id) = jid {
                        if signal == Signal::SIGKILL {
                            println!("Removing {} {} due to SIGKILL", job_id, pid);
                            // If foreground process was killed result is true.
                            result = self.jobs[job_id].state == JobState::Foreground;
                            self.remove_pid_from_jobs(pid);
                        }
                    }
                }

                // TODO: Handle this case.
                WaitStatus::Continued(pid) => {
                    println!("{} continued", pid);
                    let jid = self.pid_to_jid(pid);
                    if let Some(job_id) = jid {
                        println!("Moving {} due to background", job_id);
                        self.jobs[job_id].state = JobState::Background;
                    }
                }

                WaitStatus::StillAlive => {
                    println!("Children still alive");
                }
                _ => println!("Ptrace event"),
            },

            Err(e) => println!("Wait error {}", e),
        }

        result
    }

    fn pid_to_jid(&self, pid: Pid) -> Option<usize> {
        self.jobs.iter().position(|job| (*job).pid == pid)
    }

    fn is_inbuilt_cmd(cmd: &str) -> bool {
        if cmd.starts_with("jobs")
            || cmd.starts_with("fg")
            || cmd.starts_with("bg")
            || cmd.starts_with("quit")
        {
            return true;
        }
        false
    }

    fn remove_pid_from_jobs(&mut self, pid: Pid) {
        let job_id = self.pid_to_jid(pid);
        if let Some(jid) = job_id {
            self.jobs.remove(jid);
        } else {
            println!("Can't find {} in jobs list", pid);
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
        quit_initiated: false,
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

    // Create epoll fd to monitor stdin for commands and signal fd for signals.
    let epoll_fd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    perform_epoll_op(epoll_fd, EpollOp::EpollCtlAdd, libc::STDIN_FILENO);
    perform_epoll_op(epoll_fd, EpollOp::EpollCtlAdd, sfd.as_raw_fd());

    let mut print_prompt = true;
    loop {
        if print_prompt {
            print!("tsh> ");
        }
        io::stdout().flush().unwrap();
        let mut events: [EpollEvent; 2] = [EpollEvent::empty(), EpollEvent::empty()];
        let num_events = epoll_wait(epoll_fd, &mut events, -1).unwrap();
        for i in 0..num_events {
            let fd = events[i].data();
            let stdin_fd = libc::STDIN_FILENO as u64;
            let sfd_u64 = sfd.as_raw_fd() as u64;
            print_prompt = true;
            if fd == sfd_u64 {
                println!("In signal handling");
                match sfd.read_signal() {
                    // Handle signal.
                    Ok(Some(sig)) => {
                        match sig.ssi_signo as i32 {
                            libc::SIGCHLD => {
                                println!("Processing SIGCHLD");
                                // If foreground process is stopped or killed /
                                // exited then listen again to stdin for the
                                // next command.
                                if shell.reap_children() {
                                    println!("Reaped foreground process");
                                    perform_epoll_op(
                                        epoll_fd,
                                        EpollOp::EpollCtlAdd,
                                        libc::STDIN_FILENO,
                                    );
                                }
                            }

                            libc::SIGINT => {
                                println!("Processing SIGINT");
                                shell.send_signal_to_fg(Signal::SIGINT);
                            }

                            libc::SIGTSTP => {
                                println!("Processing SIGTSTP");
                                shell.send_signal_to_fg(Signal::SIGTSTP);
                            }

                            s => println!("Processing {}", s),
                        }
                    }
                    // No signal occured.
                    Ok(None) => (),
                    // Some error happened.
                    Err(e) => println!("Error reading signal: {}", e),
                }
            } else if fd == stdin_fd {
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
                        if !cmd.is_empty() {
                            println!("New cmd: {}", cmd);
                            let is_fg = !cmd.ends_with("&");
                            let is_inbuilt_cmd = Shell::is_inbuilt_cmd(&cmd);
                            if is_fg && !is_inbuilt_cmd {
                                perform_epoll_op(
                                    epoll_fd,
                                    EpollOp::EpollCtlDel,
                                    libc::STDIN_FILENO,
                                );
                            }

                            if is_inbuilt_cmd {
                                shell.run_in_built_cmd(&cmd);
                            } else {
                                // Only print the shell prompt if the fork was
                                // successful and the process was a non-foreground
                                // process.
                                if shell.fork_and_run_cmd(cmd, is_fg) {
                                    print_prompt = !is_fg;
                                }
                            }
                        }
                    }

                    Err(e) => println!("Error reading cmd: {}", e),
                }
            } else {
                println!("Unknown event on: {}", fd);
            }
        }
    }
}
