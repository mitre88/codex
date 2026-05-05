use codex_backend_client::Client as BackendClient;
use codex_backend_client::CodexWorkspaceMessage;
use codex_login::AuthManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio::time::interval;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const ANNOUNCEMENT_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);
const ANNOUNCEMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn spawn_announcement_poller(
    auth_manager: Arc<AuthManager>,
    chatgpt_base_url: String,
    shutdown_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = interval(ANNOUNCEMENT_POLL_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                _ = interval.tick() => {
                    poll_announcements(&auth_manager, &chatgpt_base_url).await;
                }
            }
        }
    })
}

async fn poll_announcements(auth_manager: &AuthManager, chatgpt_base_url: &str) {
    match timeout(
        ANNOUNCEMENT_FETCH_TIMEOUT,
        fetch_announcements(auth_manager, chatgpt_base_url),
    )
    .await
    {
        Ok(Ok(announcements)) => {
            debug!(
                announcement_count = announcements.len(),
                "workspace announcement poll completed"
            );
        }
        Ok(Err(err)) => {
            debug!(?err, "workspace announcement poll failed");
        }
        Err(_) => {
            debug!("workspace announcement poll timed out");
        }
    }
}

async fn fetch_announcements(
    auth_manager: &AuthManager,
    chatgpt_base_url: &str,
) -> anyhow::Result<Vec<CodexWorkspaceMessage>> {
    let Some(auth) = auth_manager.auth().await else {
        return Ok(Vec::new());
    };
    if !auth.uses_codex_backend() {
        return Ok(Vec::new());
    }

    let client = BackendClient::from_auth(chatgpt_base_url.to_owned(), &auth)?;
    let messages = client.list_workspace_messages().await?;
    // Preserve backend ranking; the API returns workspace messages ordered by created_at.
    Ok(messages.announcements().cloned().collect())
}
