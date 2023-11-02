/*
Copyright 2022 The Kuasar Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#![cfg(feature = "wasmedge")]

use std::{fs::OpenOptions, process::Command, sync::Arc};

use cgroups_rs::{Cgroup, CgroupPid};
use containerd_shim::{
    api::{CreateTaskRequest, ExecProcessRequest, Status},
    asynchronous::{
        container::{ContainerFactory, ContainerTemplate, ProcessFactory},
        monitor::{monitor_subscribe, monitor_unsubscribe},
        processes::{ProcessLifecycle, ProcessTemplate},
        task::TaskService,
        util::{mkdir, mount_rootfs, read_spec},
    },
    error::Error,
    io::Stdio,
    monitor::{Subject, Topic},
    other, other_error,
    processes::Process,
    protos::{cgroups::metrics::Metrics, shim::oci::Options, types::task::ProcessInfo},
    ExitSignal,
};
use log::debug;
use nix::{sys::signal::kill, unistd::Pid};
use oci_spec::runtime::Spec;
use wasmedge_sdk::{
    config::{CommonConfigOptions, ConfigBuilder, HostRegistrationConfigOptions},
    PluginManager, Vm,
};

use crate::utils::{get_args, get_cgroup_path, get_envs, get_preopens, get_rootfs};

pub type ExecProcess = ProcessTemplate<WasmEdgeExecLifecycle>;
pub type InitProcess = ProcessTemplate<WasmEdgeInitLifecycle>;

pub type WasmEdgeContainer = ContainerTemplate<InitProcess, ExecProcess, ExecFactory>;

pub struct ExecFactory {}

pub struct WasmEdgeExecLifecycle {}

pub struct WasmEdgeInitLifecycle {
    _opts: Options,
    _bundle: String,
    spec: Spec,
    prototype_vm: Vm,
    netns: String,
    _exit_signal: Arc<ExitSignal>,
}

pub struct WasmEdgeContainerFactory {
    prototype_vm: Vm,
    pub(crate) netns: String,
}

impl Default for WasmEdgeContainerFactory {
    fn default() -> Self {
        PluginManager::load_from_default_paths();
        let mut host_options = HostRegistrationConfigOptions::default();
        host_options = host_options.wasi(true);
        #[cfg(all(
            target_os = "linux",
            feature = "wasmedge_wasi_nn",
            target_arch = "x86_64"
        ))]
        {
            host_options = host_options.wasi_nn(true);
        }
        let config = ConfigBuilder::new(CommonConfigOptions::default())
            .with_host_registration_config(host_options)
            .build()
            .unwrap();
        let vm = Vm::new(Some(config)).map_err(anyhow::Error::msg).unwrap();
        Self {
            prototype_vm: vm,
            netns: "".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ContainerFactory<WasmEdgeContainer> for WasmEdgeContainerFactory {
    async fn create(
        &self,
        _ns: &str,
        req: &CreateTaskRequest,
    ) -> containerd_shim::Result<WasmEdgeContainer> {
        let mut spec: Spec = read_spec(req.bundle()).await?;
        spec.canonicalize_rootfs(req.bundle())
            .map_err(|e| Error::InvalidArgument(format!("could not canonicalize rootfs: {e}")))?;
        let rootfs = get_rootfs(&spec).ok_or_else(|| {
            Error::InvalidArgument("rootfs is not set in runtime spec".to_string())
        })?;
        mkdir(&rootfs, 0o711).await?;
        for m in req.rootfs() {
            mount_rootfs(m, &rootfs).await?
        }
        let stdio = Stdio::new(req.stdin(), req.stdout(), req.stderr(), req.terminal);
        let exit_signal = Arc::new(Default::default());
        let netns = self.netns.clone();
        let init_process = InitProcess::new(
            req.id(),
            stdio,
            WasmEdgeInitLifecycle {
                _opts: Default::default(),
                _bundle: req.bundle.to_string(),
                _exit_signal: exit_signal,
                spec,
                prototype_vm: self.prototype_vm.clone(),
                netns,
            },
        );
        Ok(WasmEdgeContainer {
            id: req.id.to_string(),
            bundle: req.id.to_string(),
            init: init_process,
            process_factory: ExecFactory {},
            processes: Default::default(),
        })
    }

    async fn cleanup(&self, _ns: &str, _c: &WasmEdgeContainer) -> containerd_shim::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProcessLifecycle<InitProcess> for WasmEdgeInitLifecycle {
    async fn start(&self, p: &mut InitProcess) -> containerd_shim::Result<()> {
        let spec = &p.lifecycle.spec;
        let args = get_args(spec);
        let envs = get_envs(spec);
        let rootfs = get_rootfs(spec).ok_or_else(|| {
            Error::InvalidArgument("rootfs is not set in runtime spec".to_string())
        })?;
        let mut preopens = vec![format!("/:{}", rootfs)];
        preopens.append(&mut get_preopens(spec));

        debug!(
            "start wasm with args: {:?}, envs: {:?}, preopens: {:?}",
            args, envs, preopens
        );

        match run_wasi_as_child(args, spec, p) {
            Ok(pid) => {
                p.state = Status::RUNNING;
                p.pid = pid as i32;
            }
            Err(_) => {
                debug!("failed to fork process for {}", p.id);
            }
        }

        Ok(())
    }

    async fn kill(
        &self,
        p: &mut InitProcess,
        signal: u32,
        _all: bool,
    ) -> containerd_shim::Result<()> {
        debug!("start kill process {}", p.pid);
        if p.state == Status::RUNNING && p.pid > 0 {
            debug!("kill process {}", p.pid);
            kill(
                Pid::from_raw(p.pid),
                nix::sys::signal::Signal::try_from(signal as i32).unwrap(),
            )
            .map_err(other_error!(e, "failed to kill process"))?;
        }
        Ok(())
    }

    async fn delete(&self, p: &mut InitProcess) -> containerd_shim::Result<()> {
        if let Some(cgroup_path) = get_cgroup_path(&p.lifecycle.spec) {
            // Add child process to Cgroup
            Cgroup::load(
                cgroups_rs::hierarchies::auto(),
                cgroup_path.trim_start_matches('/'),
            )
            .delete()
            .map_err(other_error!(
                e,
                format!("failed to delete cgroup: {}", cgroup_path)
            ))?;
        }
        Ok(())
    }

    async fn update(
        &self,
        _p: &mut InitProcess,
        _resources: &oci_spec::runtime::LinuxResources,
    ) -> containerd_shim::Result<()> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }

    async fn stats(&self, p: &InitProcess) -> containerd_shim::Result<Metrics> {
        debug!("get stats of process {}", p.pid);
        if p.pid <= 0 {
            return Err(other!(
                "failed to collect metrics because init process is {}",
                p.pid
            ));
        }
        // Because Wasm Applications execute the instructions inside the host Wasm
        // Runtime, we should read the metrics from Cgroup for the CPU, memory,
        // and filesystem usage.
        containerd_shim::cgroup::collect_metrics(p.pid as u32)
    }

    async fn ps(&self, p: &InitProcess) -> containerd_shim::Result<Vec<ProcessInfo>> {
        let mut process_info = ProcessInfo::new();
        process_info.pid = p.pid as u32;
        return Ok(vec![process_info]);
    }
}

#[async_trait::async_trait]
impl ProcessLifecycle<ExecProcess> for WasmEdgeExecLifecycle {
    async fn start(&self, _p: &mut ExecProcess) -> containerd_shim::Result<()> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }

    async fn kill(
        &self,
        _p: &mut ExecProcess,
        _signal: u32,
        _all: bool,
    ) -> containerd_shim::Result<()> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }

    async fn delete(&self, _p: &mut ExecProcess) -> containerd_shim::Result<()> {
        Ok(())
    }

    async fn update(
        &self,
        _p: &mut ExecProcess,
        _resources: &oci_spec::runtime::LinuxResources,
    ) -> containerd_shim::Result<()> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }

    async fn stats(&self, _p: &ExecProcess) -> containerd_shim::Result<Metrics> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }

    async fn ps(&self, _p: &ExecProcess) -> containerd_shim::Result<Vec<ProcessInfo>> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ProcessFactory<ExecProcess> for ExecFactory {
    async fn create(&self, _req: &ExecProcessRequest) -> containerd_shim::Result<ExecProcess> {
        Err(Error::Unimplemented(
            "exec not supported for wasm containers".to_string(),
        ))
    }
}

pub fn maybe_open_stdio(path: &str) -> Result<Option<std::fs::File>, std::io::Error> {
    if path.is_empty() {
        return Ok(None);
    }

    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => Ok(Some(f)),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(err),
        },
    }
}

pub enum RunError {
    IO(std::io::Error),
    NoRootInSpec,
    Cgroup,
}

fn run_wasi_as_child(args: Vec<String>, spec: &Spec, p: &InitProcess) -> Result<u32, RunError> {
    let netns = &*p.lifecycle.netns;
    let mut cmd = args[0].clone();
    let stripped = args[0].strip_prefix(std::path::MAIN_SEPARATOR);
    if let Some(stripped_cmd) = stripped {
        cmd = stripped_cmd.to_string();
    }
    let rootfs = p
        .lifecycle
        .spec
        .root()
        .as_ref()
        .ok_or(RunError::NoRootInSpec)?
        .path();
    let mod_path = rootfs.join(cmd);

    let mut child = Command::new("wasmkeeper");

    let stdio = p.stdio.clone();
    if let Some(stdin) = maybe_open_stdio(&stdio.stdin).map_err(RunError::IO)? {
        child.stdin(stdin);
    }
    if let Some(stdout) = maybe_open_stdio(&stdio.stdout).map_err(RunError::IO)? {
        child.stdout(stdout);
    }
    if let Some(stderr) = maybe_open_stdio(&stdio.stderr).map_err(RunError::IO)? {
        child.stderr(stderr);
    }

    let pid = child
        .arg("--netns")
        .arg(netns)
        .arg("--mod-path")
        .arg(mod_path)
        .spawn()
        .map_err(|e| RunError::IO(e))?
        .id();

    if let Some(cgroup_path) = get_cgroup_path(spec) {
        // Add child process to Cgroup
        if let Err(_) = Cgroup::new(
            cgroups_rs::hierarchies::auto(),
            cgroup_path.trim_start_matches('/'),
        )
        .and_then(|cgroup| cgroup.add_task_by_tgid(CgroupPid::from(pid as u64)))
        {
            println!("failed to add to cgroup");
            return Err(RunError::Cgroup);
        }
    }

    Ok(pid)
}

// any wasm runtime implementation should implement this function
pub async fn process_exits<F>(task: &TaskService<F, WasmEdgeContainer>) {
    let containers = task.containers.clone();
    let exit_signal = task.exit.clone();
    let mut s = monitor_subscribe(Topic::Pid)
        .await
        .expect("monitor subscribe failed");
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = exit_signal.wait() => {
                    debug!("sandbox exit, should break");
                    monitor_unsubscribe(s.id).await.unwrap_or_default();
                    return;
                },
                res = s.rx.recv() => {
                    if let Some(e) = res {
                        if let Subject::Pid(pid) = e.subject {
                            debug!("receive exit event: {}", &e);
                            let exit_code = e.exit_code;
                            for (_k, cont) in containers.lock().await.iter_mut() {
                                // pid belongs to container init process
                                if cont.init.pid == pid {
                                    // set exit for init process
                                    cont.init.set_exited(exit_code).await;
                                    break;
                                }

                                // pid belongs to container common process
                                for (_exec_id, p) in cont.processes.iter_mut() {
                                    // set exit for exec process
                                    if p.pid == pid {
                                        p.set_exited(exit_code).await;
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        monitor_unsubscribe(s.id).await.unwrap_or_default();
                        return;
                    }
                }
            }
        }
    });
}
