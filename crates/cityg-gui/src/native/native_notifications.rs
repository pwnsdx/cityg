use super::*;

impl AppModel {
    pub(super) fn notify_background_messages(&self, added: usize) {
        if self.window_active || added == 0 {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        let Some(latest) = self.messages.last() else {
            return;
        };

        let sender = self.resolve_sender_label(latest);
        let preview = message_notification_preview(&latest.plaintext);
        let room = room_notification_label(&session.room_id);
        let body = if added == 1 {
            format!("{sender}: {preview}")
        } else {
            format!("{added} new messages. Latest from {sender}: {preview}")
        };
        post_native_notification("City-G", Some(&room), &body);
    }
}

fn room_notification_label(room_id: &str) -> String {
    if room_id.len() <= 24 {
        format!("Room {room_id}")
    } else {
        format!(
            "Room {}…{}",
            &room_id[..12],
            &room_id[room_id.len().saturating_sub(8)..]
        )
    }
}

fn message_notification_preview(plaintext: &str) -> String {
    let mut preview = plaintext.split_whitespace().collect::<Vec<_>>().join(" ");
    if preview.is_empty() {
        preview = "(empty message)".to_string();
    }
    if preview.chars().count() > 90 {
        preview = preview.chars().take(87).collect::<String>() + "...";
    }
    preview
}

#[cfg(all(target_os = "macos", not(test)))]
pub(super) fn post_native_notification(title: &str, subtitle: Option<&str>, body: &str) {
    let title = escape_applescript_fragment(title);
    let subtitle = subtitle.map(escape_applescript_fragment);
    let body = escape_applescript_fragment(body);

    let mut script = format!("display notification \"{body}\" with title \"{title}\"");
    if let Some(subtitle) = subtitle.filter(|text| !text.is_empty()) {
        script.push_str(&format!(" subtitle \"{subtitle}\""));
    }

    let _ = std::thread::Builder::new()
        .name("cityg-native-notification".to_string())
        .spawn(move || {
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .status();
        });
}

#[cfg(any(test, not(target_os = "macos")))]
pub(super) fn post_native_notification(_: &str, _: Option<&str>, _: &str) {}

#[cfg(all(target_os = "macos", not(test)))]
fn escape_applescript_fragment(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
