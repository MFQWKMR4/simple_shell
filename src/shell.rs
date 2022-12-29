
use crate::{helper::DynError};
use nix::{
    libc,
    sys::{
        signal::{killpg, signal, SigHandler, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{self, dup2, execvp, fork, pipe, setpgid, tcgetpgrp, tcsetpgrp, ForkResult, Pid},
};
use rustyline::{error::ReadlineError, Editor};
use signal_hook::{consts::*, iterator::Signals};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::CString,
    mem::replace,
    path::PathBuf,
    process::exit,
    sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender},
    thread,
};

fn syscall<F,T>(f: F) -> Result<T, nix::Error>
where
    F: Fn() -> Result<T, nix::Error>
{
    loop {
        match f() {
            Err(nix::Error::EINTR) => (),
            result => return result,
        }
    }
}

enum WorkerMsg {
    Signal(i32),
    Cmd(String),
}

enum ShellMsg {
    Continue(i32),
    Quit(i32),
}

#[derive(Debug)]
pub struct Shell {
    logfile: String
}

impl Shell {
    pub fn new(logfile: &str) -> Self {
        Shell { logfile: logfile.to_string() }
    }

    pub fn run(&self) -> Result<(), DynError> {
        unsafe { signal(Signal::SIGTTOU, SigHandler::SigIgn).unwrap() };

        let mut rl = Editor::<()>::new()?;
        if let Err(e) = rl.load_history(&self.logfile) {
            eprintln!("zerosh: failed to load history file: {e}");
        }

        let (worker_tx, worker_rx) = channel();
        let (shell_tx, shell_rx) = sync_channel(0);
        spawn_sig_handler(worker_tx.clone())?;
        Worker::new().spawn(worker_rx, shell_tx);

        let exit_val;
        let mut prev = 0;
        loop {
            let face = prev;
            // display previous exit code
            match rl.readline(&format!("zerosh {face} %> ")) {
                Ok(line) => {
                    let line_trimed = line.trim();
                    if line_trimed.is_empty() {
                        continue;
                    } else {
                        rl.add_history_entry(line_trimed);
                    }

                    worker_tx.send(WorkerMsg::Cmd(line)).unwrap();
                    match shell_rx.recv().unwrap() {
                        ShellMsg::Continue(n) => prev = n,
                        ShellMsg::Quit(n) => {
                            exit_val = n;
                            break;
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => eprintln!("zerosh: Ctrl+D to exit"),
                Err(ReadlineError::Eof) => {
                    worker_tx.send(WorkerMsg::Cmd("exit".to_string())).unwrap();
                    match shell_rx.recv().unwrap() {
                        ShellMsg::Quit(n) => {
                            exit_val = n;
                            break;
                        }
                        _ => panic!("failed to exit"),
                    }
                }
                Err(e) => {
                    eprintln!("zerosh: failed to load\n{e}");
                    exit_val = 1;
                    break;
                }
            }
        }

        if let Err(e) = rl.save_history(&self.logfile) {
            eprintln!("zerosh: failed to load history file: {e}");
        }
        exit(exit_val);
    }
}

fn spawn_sig_handler(tx: Sender<WorkerMsg>) -> Result<(), DynError> {
    let mut signals = Signals::new(&[SIGINT, SIGTSTP, SIGCHLD])?;
    thread::spawn(move || {
        for sig in signals.forever() {
            tx.send(WorkerMsg::Signal(sig)).unwrap();
        }
    });

    Ok(())
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum ProcState {
    Run,
    Stop,
}

#[derive(Debug, Clone)]
struct ProcInfo {
    state: ProcState,
    pgid: Pid,
}

#[derive(Debug)]
struct Worker {
    exit_val: i32,
    fg: Option<Pid>,
    jobs: BTreeMap<usize, (Pid, String)>,
    pgid_to_pids: HashMap<Pid, (usize, HashSet<Pid>)>,
    pid_to_info: HashMap<Pid, ProcInfo>,
    shell_pgid: Pid,
}

impl Worker {
    fn new() -> Self {
        Worker {
            exit_val: 0,
            fg: None,
            jobs: BTreeMap::new(),
            pgid_to_pids: HashMap::new(),
            pid_to_info: HashMap::new(),
            shell_pgid: tcgetpgrp(libc::STDIN_FILENO).unwrap(),
        }
    }

    fn spawn(mut self, worker_rx: Receiver<WorkerMsg>, shell_tx: SyncSender<ShellMsg>) {
        thread::spawn(move || {
            for msg in worker_rx.iter() {
                match msg {
                    WorkerMsg::Cmd(line) => {
                        match parse_cmd(&line) {
                            Ok(cmd) => {
                                if self.built_in_cmd(&cmd, &shell_tx) {
                                    continue;
                                }

                                if !self.spawn_child(&line, &cmd) {
                                    shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
                                }
                            }
                            Err(e) => {
                                eprintln!("zerosh: {e}");
                                shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
                            }
                        }
                    }
                    WorkerMsg::Signal(SIGCHLD) => {
                        self.wait_child(&shell_tx);
                    }
                    _ => (),
                }
            }
        });
    }

    fn spawn_child(&mut self, line: &str, cmd: &[(&str, Vec<&str>)]) -> bool {
        assert_ne!(cmd.len(),0);

        let job_id = if let Some(id) = self.get_new_job_id() {
            id
        } else {
            eprintln!("zerosh: reached the max number of managable jobs");
            return false;
        };

        if cmd.len() > 2 {
            eprintln!("zerosh: no support for pipe that consists of more than 2 commands");
            return false;
        }

        let mut input = None;
        let mut output = None;
        if cmd.len() == 2 {
            let p = pipe().unwrap();
            input = Some(p.0);
            output = Some(p.1);
        }

        let cleanup_pipe = CleanUp {
            f: || {
                if let Some(fd) = input {
                    syscall(|| unistd::close(fd)).unwrap();
                }
                if let Some(fd) = output {
                    syscall(|| unistd::close(fd)).unwrap();
                }
            },
        };

        let pgid;

        match fork_exec(Pid::from_raw(0), cmd[0].0, &cmd[0].1, None, output) {
            Ok(child) => {
                pgid = child;
            }
            Err(e) => {
                eprintln!("zerosh: error at fork process: {e}");
                return false;
            }
        }
        
        let info = ProcInfo {
            state: ProcState::Run,
            pgid,
        };
        let mut pids = HashMap::new();
        pids.insert(pgid, info.clone());

        if cmd.len() == 2 {
            match fork_exec(pgid, cmd[1].0, &cmd[1].1, input, None) {
                Ok(child) => {
                    pids.insert(child, info);
                }
                Err(e) => {
                    eprintln!("zerosh: error at fork process: {e}");
                    return false;
                }
            }
        }

        std::mem::drop(cleanup_pipe);

        self.fg = Some(pgid);
        self.insert_job(job_id, pgid, pids, line);
        tcsetpgrp(libc::STDIN_FILENO, pgid).unwrap();

        true
    }

    fn wait_child(&mut self, shell_tx: &SyncSender<ShellMsg>) {
        let flag = Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WNOHANG | WaitPidFlag::WCONTINUED);

        loop {
            match syscall(|| waitpid(Pid::from_raw(-1), flag)) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    self.exit_val = status;
                    self.process_term(pid, shell_tx);
                }
                Ok(WaitStatus::Signaled(pid, sig, core)) => {
                    eprintln!(
                        "\nzerosh: signal terminated child process{}: pid = {pid}, signal = {sig}",
                        if core { "(core dump)"} else {""}
                    );

                    self.exit_val = sig as i32 + 128;
                    self.process_term(pid, shell_tx);
                }
                Ok(WaitStatus::Stopped(pid, _sig)) => {
                    self.process_stop(pid, shell_tx);
                },
                Ok(WaitStatus::Continued(pid)) => self.process_continue(pid),
                Ok(WaitStatus::StillAlive) => return,
                Err(nix::Error::ECHILD) => return,
                Err(e) => {
                    eprintln!("\nzerosh: failed to wait: {e}");
                    exit(1);
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(WaitStatus::PtraceEvent(pid,_,_) | WaitStatus::PtraceSyscall(pid)) => {
                    self.process_stop(pid, shell_tx)
                }
            }
        }

    }

    fn get_new_job_id(&self) -> Option<usize> {
        for i in 0..=usize::MAX {
            if !self.jobs.contains_key(&i) {
                return Some(i);
            }
        }
        None
    }

    fn insert_job(&mut self, job_id: usize, pgid: Pid, pids: HashMap<Pid, ProcInfo>, line: &str) {
        assert!(!self.jobs.contains_key(&job_id));
        self.jobs.insert(job_id, (pgid, line.to_string()));

        let mut procs = HashSet::new();
        for (pid, info) in pids {
            procs.insert(pid);

            assert!(!self.pid_to_info.contains_key(&pid));
            self.pid_to_info.insert(pid, info);
        }

        assert!(!self.pgid_to_pids.contains_key(&pgid));
        self.pgid_to_pids.insert(pgid, (job_id, procs));
    }

    fn process_term(&mut self, pid: Pid, shell_tx: &SyncSender<ShellMsg>) {
        if let Some((job_id, pgid)) = self.remove_pid(pid) {
            self.manage_job(job_id, pgid, shell_tx);
        }
    }

    fn process_stop(&mut self, pid: Pid, _shell_tx: &SyncSender<ShellMsg>) {
        self.set_pid_state(pid, ProcState::Stop);
    }

    fn process_continue(&mut self, pid: Pid) {
        self.set_pid_state(pid, ProcState::Run);
    }

    fn set_pid_state(&mut self, pid: Pid, state: ProcState) -> Option<ProcState> {
        let info = self.pid_to_info.get_mut(&pid)?;
        Some(replace(&mut info.state, state))
    }

    fn remove_pid(&mut self, pid: Pid) -> Option<(usize, Pid)> {
        let pgid = self.pid_to_info.get(&pid)?.pgid;
        let it = self.pgid_to_pids.get_mut(&pgid)?;
        it.1.remove(&pid);
        let job_id = it.0;
        Some((job_id, pgid))
    }

    fn manage_job(&mut self, job_id: usize, pgid: Pid, shell_tx: &SyncSender<ShellMsg>) {
        let is_fg = self.fg.map_or(false, |x| pgid == x);
        let line = &self.jobs.get(&job_id).unwrap().1;
        if is_fg {
            if self.is_group_empty(pgid) {
                eprintln!("[{job_id}] 終了\t{line}");
                self.remove_job(job_id);
                self.set_shell_fg(shell_tx);
            } else if self.is_group_stop(pgid).unwrap() {
                eprintln!("\n[{job_id}] 停止\t{line}");
                self.set_shell_fg(shell_tx);
            }
        } else {
            if self.is_group_empty(pgid) {
                eprintln!("\n[{job_id}] 終了\t{line}");
                self.remove_job(job_id);
            }
        }
    }

    fn remove_job(&mut self, job_id: usize) {
        if let Some((pgid, _)) = self.jobs.remove(&job_id) {
            if let Some((_, pids)) = self.pgid_to_pids.remove(&pgid) {
                assert!(pids.is_empty());
            }
        }
    }

    fn is_group_empty(&self, pgid: Pid) -> bool {
        self.pgid_to_pids.get(&pgid).unwrap().1.is_empty()
    }

    fn is_group_stop(&self, pgid: Pid) -> Option<bool> {
        for pid in self.pgid_to_pids.get(&pgid)?.1.iter() {
            if self.pid_to_info.get(pid).unwrap().state == ProcState::Run {
                return Some(false);
            }
        }
        Some(true)
    }

    fn set_shell_fg(&mut self, shell_tx: &SyncSender<ShellMsg>) {
        self.fg = None;
        tcsetpgrp(libc::STDIN_FILENO, self.shell_pgid).unwrap();
        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
    }

    fn built_in_cmd(&mut self, cmd: &[(&str, Vec<&str>)], shell_tx: &SyncSender<ShellMsg>) -> bool {
        if cmd.len() > 1 {
            return false;
        }
    
        match cmd[0].0 {
            "exit" => self.run_exit(&cmd[0].1, shell_tx),
            "jobs" => self.run_jobs(shell_tx),
            "fg" => self.run_fg(&cmd[0].1, shell_tx),
            "cd" => self.run_cd(&cmd[0].1, shell_tx),
            _ => false
        }
    }

    fn run_exit(&mut self, args: &[&str], shell_tx: &SyncSender<ShellMsg>) -> bool {
        if !self.jobs.is_empty() {
            eprintln!("can't exit because of job execution");
            self.exit_val = 1;
            shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
            return true;
        }

        let exit_val = if let Some(s) = args.get(1) {
            if let Ok(n) = (*s).parse::<i32>() {
                n
            } else {
                eprintln!("{s} is invalid argument");
                self.exit_val = 1;
                shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
                return true;
            }
        } else {
            self.exit_val
        };

        shell_tx.send(ShellMsg::Quit(exit_val)).unwrap();
        true
    }
    fn run_fg(&mut self, args: &[&str], shell_tx: &SyncSender<ShellMsg>) -> bool {
        self.exit_val = 1;

        if args.len() < 2 {
            eprintln!("usage: fg <number>");
            shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
            return true;
        }

        if let Ok(n) = args[1].parse::<usize>() {
            if let Some((pgid, cmd)) = self.jobs.get(&n) {
                eprintln!("[{n}] resume¥\t{cmd}");

                self.fg = Some(*pgid);
                tcsetpgrp(libc::STDIN_FILENO, *pgid).unwrap();

                killpg(*pgid, Signal::SIGCONT).unwrap();
                return true;
            }
        }

        eprintln!("job {} was not found", args[1]);
        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
        true
    }
    fn run_jobs(&mut self, shell_tx: &SyncSender<ShellMsg>) -> bool {
        for (job_id, (pgid, cmd)) in &self.jobs {
            let state = if self.is_group_stop(*pgid).unwrap() {
                "停止中"
            } else {
                "実行中"
            };
            println!("[{job_id}] {state}\t{cmd}")
        }
        self.exit_val = 0;
        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
        true
    }
    fn run_cd(&mut self, args: &[&str], shell_tx: &SyncSender<ShellMsg>) -> bool {
        let path = if args.len() == 1 {
            dirs::home_dir()
                .or_else(|| Some(PathBuf::from("/")))
                .unwrap()
        } else {
            PathBuf::from(args[1])
        };

        if let Err(e) = std::env::set_current_dir(&path) {
            self.exit_val = 1;
            eprintln!("cd fail: {e}");
        } else {
            self.exit_val = 0;
        }

        shell_tx.send(ShellMsg::Continue(self.exit_val)).unwrap();
        true
    }
}

type CmdResult<'a> = Result<Vec<(&'a str, Vec<&'a str>)>, DynError>;

fn parse_cmd_one(line: &str) -> Result<(&str, Vec<&str>), DynError> {
    let cmd: Vec<&str> = line.split(' ').collect();
    let mut filename = "";
    let mut args = Vec::new();
    for (n, s) in cmd.iter().filter(|s| !s.is_empty()).enumerate() {
        if n == 0 {
            filename = *s;
        }
        args.push(*s);
    }

    if filename.is_empty() {
        Err("empty command".into())
    } else {
        Ok((filename, args))
    }
}

fn parse_pipe(line: &str) -> Vec<&str> {
    line.split('|').collect()
}

fn parse_cmd(line: &str) -> CmdResult {
    let cmds = parse_pipe(line);
    if cmds.is_empty() {
        return Err("empty command".into());
    }

    let mut result = Vec::new();
    for cmd in cmds {
        let (filename, args) = parse_cmd_one(cmd)?;
        result.push((filename, args));
    }

    Ok(result)
}

struct CleanUp<F>
where
    F: Fn(),
{
    f: F,
}

impl<F> Drop for CleanUp<F>
where
    F: Fn(),
{
    fn drop(&mut self) {
        (self.f)()
    }
}

fn fork_exec(
    pgid: Pid,
    filename: &str,
    args: &[&str],
    input: Option<i32>,
    output: Option<i32>,
) -> Result<Pid, DynError> {
    let filename = CString::new(filename).unwrap();
    let args: Vec<CString> = args.iter().map(|s| CString::new(*s).unwrap()).collect();

    match syscall(|| unsafe { fork() })? {
        ForkResult::Parent { child, .. } => {
            setpgid(child, pgid).unwrap();
            Ok(child)
        }
        ForkResult::Child => {
            setpgid(Pid::from_raw(0), pgid).unwrap();

            if let Some(infd) = input {
                syscall(|| dup2(infd, libc::STDIN_FILENO)).unwrap();
            }
            if let Some(outfd) = output {
                syscall(|| dup2(outfd, libc::STDOUT_FILENO)).unwrap();
            }

            for i in 3..=6 {
                let _ = syscall(|| unistd::close(i));
            }

            match execvp(&filename, &args) {
                Err(_) => {
                    unistd::write(libc::STDERR_FILENO, "unknown command\n".as_bytes()).ok();
                    exit(1);
                }
                Ok(_) => unreachable!(),
            }
        }
    }
}