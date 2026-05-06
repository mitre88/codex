#![cfg(not(target_os = "windows"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use codex_login::CODEX_API_KEY_ENV_VAR;
use core_test_support::responses;
use core_test_support::test_codex_exec::test_codex_exec;
use predicates::str::contains;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_appends_piped_stdin_to_prompt_argument() -> anyhow::Result<()> {
    let test = test_codex_exec();
    let server = responses::start_mock_server().await;
    let body = responses::sse(vec![
        responses::ev_response_created("resp1"),
        responses::ev_assistant_message("m1", "fixture hello"),
        responses::ev_completed("resp1"),
    ]);
    let response_mock = responses::mount_sse_once(&server, body).await;

    // echo "my output" | codex exec --skip-git-repo-check -C <cwd> -m gpt-5.1 "Summarize this concisely"
    test.cmd_with_server(&server)
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-m")
        .arg("gpt-5.1")
        .arg("Summarize this concisely")
        .write_stdin("my output\n")
        .assert()
        .success();

    let request = response_mock.single_request();
    assert!(
        request.has_message_with_input_texts("user", |texts| {
            texts == ["Summarize this concisely\n\n<stdin>\nmy output\n</stdin>".to_string()]
        }),
        "request should include a user message with the prompt plus piped stdin context"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_ignores_empty_piped_stdin_when_prompt_argument_is_present() -> anyhow::Result<()> {
    let test = test_codex_exec();
    let server = responses::start_mock_server().await;
    let body = responses::sse(vec![
        responses::ev_response_created("resp1"),
        responses::ev_assistant_message("m1", "fixture hello"),
        responses::ev_completed("resp1"),
    ]);
    let response_mock = responses::mount_sse_once(&server, body).await;

    // printf "" | codex exec --skip-git-repo-check -C <cwd> -m gpt-5.1 "Summarize this concisely"
    test.cmd_with_server(&server)
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-m")
        .arg("gpt-5.1")
        .arg("Summarize this concisely")
        .write_stdin("")
        .assert()
        .success();

    let request = response_mock.single_request();
    assert!(
        request.has_message_with_input_texts("user", |texts| texts
            == ["Summarize this concisely".to_string()]),
        "request should preserve the prompt when stdin is empty"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_with_prompt_does_not_wait_for_empty_open_stdin_pipe() -> anyhow::Result<()> {
    let test = test_codex_exec();
    let server = responses::start_mock_server().await;
    let body = responses::sse(vec![
        responses::ev_response_created("resp1"),
        responses::ev_assistant_message("m1", "fixture hello"),
        responses::ev_completed("resp1"),
    ]);
    let response_mock = responses::mount_sse_once(&server, body).await;

    let mut fds = [-1; 2];
    // Safety: `fds` is a valid two-element out array for `pipe`.
    let pipe_result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(pipe_result, 0, "pipe should be created");
    // Safety: both fds were returned by `pipe` and are now owned by these values.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // Keep the write end open without sending data so stdin is not ready and
    // would block if exec tried to append optional stdin.
    let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // assert_cmd always replaces stdin with a pipe it owns; use tokio::process
    // here so the child receives the open read end created above.
    let base = format!("{}/v1", server.uri());
    let mut cmd = tokio::process::Command::new(
        codex_utils_cargo_bin::cargo_bin("codex-exec").expect("should find binary for codex-exec"),
    );
    cmd.current_dir(test.cwd_path())
        .env("CODEX_HOME", test.home_path())
        .env("CODEX_SQLITE_HOME", test.home_path())
        .env(CODEX_API_KEY_ENV_VAR, "dummy")
        .arg("-c")
        .arg(format!(
            "openai_base_url={}",
            serde_json::to_string(&base).expect("serialize TOML string literal")
        ))
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-m")
        .arg("gpt-5.1")
        .arg("Summarize this concisely")
        .stdin(Stdio::from(read_fd))
        .kill_on_drop(true);

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let mut stdout = child.stdout.take().expect("stdout should be piped");
    let mut stderr = child.stderr.take().expect("stderr should be piped");
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).await.map(|_| output)
    });
    let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(status) => status?,
        Err(err) => {
            child.kill().await?;
            child.wait().await?;
            let stdout = stdout_task.await??;
            let stderr = stderr_task.await??;
            panic!(
                "{err}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
    };
    let stdout = stdout_task.await??;
    let stderr = stderr_task.await??;
    assert!(
        status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    let request = response_mock.single_request();
    assert!(
        request.has_message_with_input_texts("user", |texts| texts
            == ["Summarize this concisely".to_string()]),
        "request should preserve the prompt when stdin is an open pipe with no immediate data"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_dash_prompt_reads_stdin_as_the_prompt() -> anyhow::Result<()> {
    let test = test_codex_exec();
    let server = responses::start_mock_server().await;
    let body = responses::sse(vec![
        responses::ev_response_created("resp1"),
        responses::ev_assistant_message("m1", "fixture hello"),
        responses::ev_completed("resp1"),
    ]);
    let response_mock = responses::mount_sse_once(&server, body).await;

    // echo "prompt from stdin" | codex exec --skip-git-repo-check -C <cwd> -m gpt-5.1 -
    test.cmd_with_server(&server)
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-m")
        .arg("gpt-5.1")
        .arg("-")
        .write_stdin("prompt from stdin\n")
        .assert()
        .success();

    let request = response_mock.single_request();
    assert!(
        request.has_message_with_input_texts("user", |texts| {
            texts == ["prompt from stdin\n".to_string()]
        }),
        "dash prompt should preserve the existing forced-stdin behavior"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_without_prompt_argument_reads_piped_stdin_as_the_prompt() -> anyhow::Result<()> {
    let test = test_codex_exec();
    let server = responses::start_mock_server().await;
    let body = responses::sse(vec![
        responses::ev_response_created("resp1"),
        responses::ev_assistant_message("m1", "fixture hello"),
        responses::ev_completed("resp1"),
    ]);
    let response_mock = responses::mount_sse_once(&server, body).await;

    // echo "prompt from stdin" | codex exec --skip-git-repo-check -C <cwd> -m gpt-5.1
    test.cmd_with_server(&server)
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-m")
        .arg("gpt-5.1")
        .write_stdin("prompt from stdin\n")
        .assert()
        .success();

    let request = response_mock.single_request();
    assert!(
        request.has_message_with_input_texts("user", |texts| {
            texts == ["prompt from stdin\n".to_string()]
        }),
        "missing prompt argument should preserve the existing piped-stdin prompt behavior"
    );

    Ok(())
}

#[test]
fn exec_without_prompt_argument_rejects_empty_piped_stdin() {
    let test = test_codex_exec();

    // printf "" | codex exec --skip-git-repo-check -C <cwd>
    test.cmd()
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(contains("No prompt provided via stdin."));
}

#[test]
fn exec_dash_prompt_rejects_empty_piped_stdin() {
    let test = test_codex_exec();

    // printf "" | codex exec --skip-git-repo-check -C <cwd> -
    test.cmd()
        .arg("--skip-git-repo-check")
        .arg("-C")
        .arg(test.cwd_path())
        .arg("-")
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(contains("No prompt provided via stdin."));
}
