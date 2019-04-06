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
#[macro_use]
extern crate log;
extern crate env_logger;

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
    pub fn new() -> Shell {
        Shell {
            fg: None,
            jobs: vec![],
            quit_initiated: false,
        }
    }

    // Returns (if a signal was sent to any job in the shell,
    // stdin needs to be blocked).
    pub fn run_in_built_cmd(&mut self, cmd: &str) -> (bool, bool) {
        if cmd.starts_with("quit") {
            debug!("quit");
            // If no jobs exist then exit immediately.
            if self.jobs.is_empty() {
                process::exit(0);
            }

            // If jobs exist then kill all children processes. The shell would
            // exit after processes are reaped in |reap_children|.
            self.jobs
                .iter()
                .for_each(|job| kill(Pid::from_raw(-job.pid.as_raw()), Signal::SIGKILL).unwrap());
            self.quit_initiated = true;
            return (true, false);
        } else if cmd.starts_with("jobs") {
            debug!("jobs");
            self.print_jobs();
            return (false, false);
        } else if cmd.starts_with("bg") {
            return (self.process_bg(&cmd.split_whitespace().collect()), false);
        } else if cmd.starts_with("fg") {
            return self.process_fg(&cmd.split_whitespace().collect());
        } else if cmd.starts_with("kill") {
            return (self.process_kill(&cmd.split_whitespace().collect()), false);
        }

        (false, false)
    }

    pub fn fork_and_run_cmd(&mut self, cmd: String, is_fg: bool) -> bool {
        let result = fork();
        match result {
            Ok(ForkResult::Parent { child }) => {
                debug!("In the Parent - Child's pid {}", child);
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
                debug!("In the child {}", cmd);

                // Set new process group for the child. The gid will be the pid
                // of the new process.
                match nix::unistd::setpgid(
                    nix::unistd::Pid::from_raw(0),
                    nix::unistd::Pid::from_raw(0),
                ) {
                    Err(e) => {
                        debug!("Failed to setpgid error: {}", e);
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

                // If |cmd| is invoked in background mode then the actual
                // command shouldn't have the trailing " &".
                let filtered_cmd;
                if !is_fg {
                    filtered_cmd = cmd.trim_end_matches(" &").to_string();
                    debug!("Trimmed cmd to: {}", cmd);
                } else {
                    filtered_cmd = cmd;
                }

                // If filtered_cmd="a b c" then filename="a" args=["b", "c"].
                let args = filtered_cmd.split_whitespace();
                // TODO: Handle unwrap and understand collect args.
                let mut cstring_args: Vec<std::ffi::CString> = Vec::new();
                for arg in args {
                    debug!("Arg: {}", arg);
                    cstring_args.push(CString::new(arg).unwrap());
                }
                debug!(
                    "Filtered cmd: {} filename: {}",
                    filtered_cmd,
                    cstring_args[0].to_str().unwrap()
                );

                // Parse env vars to pass in the forked process.
                let mut cstring_env: Vec<std::ffi::CString> = Vec::new();
                for (key, value) in std::env::vars_os() {
                    debug!("{:?}: {:?}", key, value);
                    let env_arg = format!("{}={}", key.to_str().unwrap(), value.to_str().unwrap());
                    cstring_env.push(CString::new(env_arg).unwrap());
                }

                match nix::unistd::execve(&cstring_args[0], &cstring_args, &cstring_env) {
                    Err(e) => {
                        // Exit the forked process if exec-ing command has failed.
                        debug!("Failed to exec {}", e);
                        process::exit(-1);
                    }
                    _ => (),
                }
            }

            Err(_) => {
                debug!("Fork failed");
                return false;
            }
        }

        true
    }

    fn print_jobs(&self) {
        debug!("Jobs");
        let mut i = 1;
        for job in &self.jobs {
            println!("[{}] {}", i, job);
            i += 1;
        }
    }

    fn send_signal_to_fg(&self, sig: Signal) {
        // Send signal to the foreground process group if it exists.
        if let Some(pid) = self.fg {
            kill(Pid::from_raw(-pid.as_raw()), sig).unwrap();
        }
    }

    // Reaps children that are ready for reaping. Returns true iff foreground
    // process is reaped.
    fn reap_children(&mut self) -> bool {
        let mut result = false;
        // First reap foreground process and then all other children.
        if let Some(pid) = self.fg {
            debug!("Wait for foreground process");
            result = self.wait_for_child(pid);
            if result {
                self.fg = None;
            }
        }

        debug!("Wait for remaining processes");
        let job_pids: Vec<Pid> = self.jobs.iter().map(|job| job.pid).collect();
        for pid in job_pids {
            self.wait_for_child(pid);
        }

        // If this is a reap after a "quit" was issued then exit the terminal.
        if self.quit_initiated {
            process::exit(0);
        }

        result
    }

    fn wait_for_child(&mut self, pid: Pid) -> bool {
        let mut result = false;
        let mut flags = WaitPidFlag::empty();
        flags.set(WaitPidFlag::WNOHANG, true);
        flags.set(WaitPidFlag::WUNTRACED, true);
        flags.set(WaitPidFlag::WCONTINUED, true);
        match waitpid(Some(pid), Some(flags)) {
            Ok(t) => match t {
                // Reap process and remove it from internal list of jobs.
                WaitStatus::Exited(pid, status) => {
                    result = true;
                    debug!("{} exited with {}", pid, status);
                    self.remove_pid_from_jobs(pid);
                }

                // Change state of the job to stopped.
                WaitStatus::Stopped(pid, _) => {
                    result = true;
                    let job_id = self.pid_to_jid(pid);
                    if let Some(jid) = job_id {
                        println!(
                            "[{}] + {} suspended {}",
                            jid + 1,
                            pid,
                            self.jobs[jid].cmd_line
                        );
                        self.jobs[jid].state = JobState::Stopped;
                    }
                }

                // Reap process and remove it from internal list of jobs.
                WaitStatus::Signaled(pid, signal, is_coredump) => {
                    debug!(
                        "{} signaled due to signal {} coredumped {}",
                        pid, signal, is_coredump
                    );
                    let job_id = self.pid_to_jid(pid);
                    if let Some(jid) = job_id {
                        debug!("Removing {} {}", jid, pid);
                        // Only print this if it's not in response to a "quit".
                        if !self.quit_initiated {
                            println!(
                                "[{}] + {} terminated {}",
                                jid + 1,
                                pid,
                                self.jobs[jid].cmd_line
                            );
                        }
                        // If foreground process was killed result is true.
                        result = self.jobs[jid].state == JobState::Foreground;
                        self.remove_pid_from_jobs(pid);
                    }
                }

                WaitStatus::Continued(pid) => {
                    debug!("{} continued", pid);
                    let job_id = self.pid_to_jid(pid);
                    if let Some(jid) = job_id {
                        debug!("Moving {} due to background", jid);
                        // Only print this if it's not in response to a "quit".
                        if !self.quit_initiated {
                            println!(
                                "[{}] + {} continued {}",
                                jid + 1,
                                pid,
                                self.jobs[jid].cmd_line
                            );
                        }
                        // TODO: Handle case when this is sent via "fg", in
                        // that case set this to JobState::Foreground and set
                        // self.fg.
                        self.jobs[jid].state = JobState::Background;
                    }
                }

                WaitStatus::StillAlive => {
                    debug!("Children still alive");
                }
                _ => debug!("Ptrace event"),
            },

            Err(e) => debug!("Wait error {}", e),
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
            || cmd.starts_with("kill")
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
            debug!("Can't find {} in jobs list", pid);
        }
    }

    // |arg| could be %1 or a <pid>.
    fn arg_to_job_id(&self, arg: &str) -> Option<usize> {
        // Extract job id from args.
        if arg.starts_with("%") {
            // TODO: Handle unwrap here.
            let j_id = i32::from_str_radix(arg.trim_start_matches("%"), 10).unwrap() as usize;

            if j_id == 0 {
                None
            } else {
                Some(j_id)
            }
        } else {
            let pid = i32::from_str_radix(arg.trim_start_matches("%"), 10).unwrap();
            self.pid_to_jid(Pid::from_raw(pid))
        }
    }

    fn process_bg(&mut self, args: &Vec<&str>) -> bool {
        debug!("bg");
        let mut result = false;
        // Do nothing if exact number of args aren't provided to "bg".
        if args.len() != 2 {
            debug!("Args len mismatch {}", args.len());
            return result;
        }

        let j_id = self.arg_to_job_id(args[1]);
        if let Some(job_id) = j_id {
            // |job_id| is guaranteed to be > 0 at this point.
            let job_index = job_id - 1;
            if job_index < self.jobs.len() {
                if self.jobs[job_index].state == JobState::Background {
                    println!("bg: job already in background");
                    return result;
                }

                debug!(
                    "Job {} Pid {} sent SIGCONT",
                    job_id, self.jobs[job_index].pid
                );
                kill(
                    Pid::from_raw(-self.jobs[job_index].pid.as_raw()),
                    signal::SIGCONT,
                )
                .unwrap();
                result = true;
            } else {
                println!("bg: {}: no such job", args[1]);
            }
        } else {
            println!("bg: {}: no such job", args[1]);
        }

        result
    }

    fn process_kill(&mut self, args: &Vec<&str>) -> bool {
        debug!("kill");
        let mut result = false;
        // Do nothing if exact number of args aren't provided to "kill".
        if args.len() != 2 {
            debug!("Args len mismatch {}", args.len());
            return result;
        }

        let j_id = self.arg_to_job_id(args[1]);
        if let Some(job_id) = j_id {
            // |job_id| is guaranteed to be > 0 at this point.
            let job_index = job_id - 1;
            if job_index < self.jobs.len() {
                debug!(
                    "Job {} Pid {} sent SIGKILL",
                    job_id, self.jobs[job_index].pid
                );
                kill(
                    Pid::from_raw(-self.jobs[job_index].pid.as_raw()),
                    signal::SIGKILL,
                )
                .unwrap();
                result = true;
            } else {
                println!("kill: {}: no such job", args[1]);
            }
        } else {
            println!("kill: {}: no such job", args[1]);
        }

        result
    }

    fn process_fg(&mut self, args: &Vec<&str>) -> (bool, bool) {
        debug!("fg");
        let mut signal_sent = false;
        let mut block_stdin = false;
        // Do nothing if exact number of args aren't provided to "kill".
        if args.len() != 2 {
            debug!("Args len mismatch {}", args.len());
            return (signal_sent, block_stdin);
        }

        let j_id = self.arg_to_job_id(args[1]);
        if let Some(job_id) = j_id {
            // |job_id| is guaranteed to be > 0 at this point.
            let job_index = job_id - 1;
            if job_index < self.jobs.len() {
                if self.jobs[job_index].state == JobState::Stopped {
                    debug!(
                        "Job {} Pid {} sent SIGCONT",
                        job_id, self.jobs[job_index].pid
                    );
                    kill(
                        Pid::from_raw(-self.jobs[job_index].pid.as_raw()),
                        signal::SIGCONT,
                    )
                    .unwrap();
                    signal_sent = true;
                    block_stdin = true;
                } else if self.jobs[job_index].state == JobState::Background {
                    println!(
                        "[{}] + {} running {}",
                        job_id, self.jobs[job_index].pid, self.jobs[job_index].cmd_line
                    );
                    self.jobs[job_index].state = JobState::Foreground;
                    self.fg = Some(self.jobs[job_index].pid);
                    // Since job state is changed here, treat this as a signal
                    // being sent. This is required so that outer loop doesn't
                    // print prompt now that a foreground process is there.
                    signal_sent = true;
                    block_stdin = true;
                } else {
                    panic!("Not reachable");
                }
            } else {
                println!("fg: {}: no such job", args[1]);
            }
        } else {
            println!("fg: {}: no such job", args[1]);
        }

        (signal_sent, block_stdin)
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
    env_logger::init();

    let mut shell = Shell::new();

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
            print_prompt = false;
            if fd == sfd_u64 {
                debug!("In signal handling");
                match sfd.read_signal() {
                    // Handle signal.
                    Ok(Some(sig)) => {
                        match sig.ssi_signo as i32 {
                            libc::SIGCHLD => {
                                print_prompt = true;
                                debug!("Processing SIGCHLD");
                                // If foreground process is stopped or killed /
                                // exited then listen again to stdin for the
                                // next command.
                                if shell.reap_children() {
                                    debug!("Reaped foreground process");
                                    perform_epoll_op(
                                        epoll_fd,
                                        EpollOp::EpollCtlAdd,
                                        libc::STDIN_FILENO,
                                    );
                                }
                            }

                            libc::SIGINT => {
                                // Needed so that any further updates on the
                                // terminal are on a newline.
                                println!();
                                debug!("Processing SIGINT");
                                shell.send_signal_to_fg(Signal::SIGINT);
                            }

                            libc::SIGTSTP => {
                                // Needed so that any further updates on the
                                // terminal are on a newline.
                                println!();
                                debug!("Processing SIGTSTP");
                                shell.send_signal_to_fg(Signal::SIGTSTP);
                            }

                            s => debug!("Processing {}", s),
                        }
                    }
                    // No signal occured.
                    Ok(None) => (),
                    // Some error happened.
                    Err(e) => debug!("Error reading signal: {}", e),
                }
            } else if fd == stdin_fd {
                debug!("In cmd handling");
                let mut cmd = String::new();
                match io::stdin().read_line(&mut cmd) {
                    Ok(_) => {
                        // If this is an EOF just make it behave like a quit.
                        if cmd.is_empty() {
                            debug!("EOF");
                            cmd = String::from("quit");
                        }

                        // Remove trailing characters.
                        cmd = cmd.trim().to_string();
                        // If a foreground process will be run then remove
                        // stdin from the monitored fds. This is required
                        // becasuse the shell should not eat the input for
                        // the process as well as the shell has to wait
                        // till the foregorund process finishes.
                        debug!("New cmd: {}", cmd);
                        let is_fg = !cmd.ends_with("&");
                        let is_inbuilt_cmd = Shell::is_inbuilt_cmd(&cmd);
                        if is_fg && !is_inbuilt_cmd {
                            perform_epoll_op(epoll_fd, EpollOp::EpollCtlDel, libc::STDIN_FILENO);
                        }

                        if is_inbuilt_cmd {
                            // Print prompt only when no signal was sent to
                            // a job. This is done because a signal sent
                            // would mean the signal handling would also
                            // print out a message which should happen
                            // before the next prompt is displayed.
                            let (signal_sent, block_stdin) = shell.run_in_built_cmd(&cmd);
                            print_prompt = !signal_sent;

                            // Can be true when an "fg" was issued.
                            if block_stdin {
                                perform_epoll_op(
                                    epoll_fd,
                                    EpollOp::EpollCtlDel,
                                    libc::STDIN_FILENO,
                                );
                            }
                        } else {
                            // If the fork was successful and the process
                            // was a non-foreground process then print the
                            // prompt. If fork was unsuccessful even then
                            // print the prompt to receive the new command.
                            if shell.fork_and_run_cmd(cmd, is_fg) {
                                print_prompt = !is_fg;
                            } else {
                                print_prompt = true;
                            }
                        }
                    }

                    Err(e) => debug!("Error reading cmd: {}", e),
                }
            } else {
                debug!("Unknown event on: {}", fd);
            }
        }
    }
}
