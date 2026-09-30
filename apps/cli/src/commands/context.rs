//! Context file commands (Phase 7, T-701).
//!
//! Inspect and edit `.ciphervault/context.json` (precedence level 3).
//! `context set` merges with existing fields; `project use` is the
//! project-scoped shortcut (and always clears the environment to prevent
//! cross-project scope leaks).

use anyhow::{bail, Result};

use super::scope::{read_context_file_at, write_context_file_at};
use crate::ContextSubcommand;

pub(crate) async fn cmd_context(sub: ContextSubcommand) -> Result<()> {
    match sub {
        ContextSubcommand::Show => {
            match read_context_file_at(&crate::util::get_workspace_root()?)? {
                Some(file) => {
                    println!("project: {}", file.project.as_deref().unwrap_or("(unset)"));
                    println!("env: {}", file.env.as_deref().unwrap_or("(unset)"));
                }
                None => println!("No context file (.ciphervault/context.json)."),
            }
            Ok(())
        }
        ContextSubcommand::Set { project, env } => {
            if project.is_none() && env.is_none() {
                bail!("pass --project and/or --env");
            }
            let existing =
                read_context_file_at(&crate::util::get_workspace_root()?)?.unwrap_or_default();
            let project = project.as_deref().or(existing.project.as_deref());
            let env = env.as_deref().or(existing.env.as_deref());
            write_context_file_at(&crate::util::get_workspace_root()?, project, env)?;
            println!("Context saved.");
            Ok(())
        }
        ContextSubcommand::Clear => {
            write_context_file_at(&crate::util::get_workspace_root()?, None, None)?;
            println!("Context cleared.");
            Ok(())
        }
    }
}
