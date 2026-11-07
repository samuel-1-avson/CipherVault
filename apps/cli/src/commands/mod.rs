//! CLI command implementations.

pub(crate) mod anchor;
pub(crate) mod approvals;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod context;
pub(crate) mod dpop;
pub(crate) mod feed;
pub(crate) mod fleet_cli;
pub(crate) mod hook;
pub(crate) mod init;
pub(crate) mod inspect;
pub(crate) mod migrate;
pub(crate) mod node;
pub(crate) mod project;
pub(crate) mod push;
pub(crate) mod recover;
pub(crate) mod recovery_key;
pub(crate) mod recovery_kit;
pub(crate) mod release;
pub(crate) mod repo;
pub(crate) mod restore;
pub(crate) mod retention;
pub(crate) mod run;
pub(crate) mod scope;
pub(crate) mod secret;
pub(crate) mod token;
pub(crate) mod track;
pub(crate) mod update;

pub(crate) use anchor::*;
pub(crate) use approvals::*;
pub(crate) use audit::*;
pub(crate) use auth::*;
pub(crate) use context::*;
pub(crate) use feed::*;
pub(crate) use fleet_cli::*;
pub(crate) use hook::*;
pub(crate) use init::*;
pub(crate) use inspect::*;
pub(crate) use migrate::*;
pub(crate) use node::*;
pub(crate) use project::*;
pub(crate) use push::*;
pub(crate) use recover::*;
pub(crate) use recovery_key::*;
pub(crate) use recovery_kit::*;
pub(crate) use release::*;
pub(crate) use repo::*;
pub(crate) use restore::*;
pub(crate) use retention::*;
pub(crate) use run::*;
pub(crate) use secret::*;
pub(crate) use token::*;
pub(crate) use track::*;
pub(crate) use update::*;

/// Routes a parsed top-level command to its implementation. Lives here —
/// not in `main.rs` — so the binary entry point stays thin wiring (parse,
/// dispatch, report) while every command implementation lives beside its
/// module. Subcommand enums stay defined next to `Cli` in the crate root
/// and are imported below.
pub(crate) async fn run_command(command: crate::Commands) -> anyhow::Result<()> {
    use crate::{
        ApproveSubcommand, AuthSubcommand, DeviceSubcommand, HookSubcommand, InviteSubcommand,
        LeaseSubcommand, NodeSubcommand, RecoverySubcommand, ReleaseSubcommand, VaultSubcommand,
        VoucherSubcommand,
    };
    use colored::Colorize;

    match command {
        crate::Commands::Update { check, reinstall } => cmd_update(check, reinstall).await,
        crate::Commands::Release { sub } => match sub {
            ReleaseSubcommand::Sign {
                tag,
                sums,
                out,
                key_file,
            } => cmd_release_sign(tag, sums, out, key_file),
            ReleaseSubcommand::Verify { tag, sums, sig } => cmd_release_verify(tag, sums, sig),
        },
        crate::Commands::Auth { sub } => match sub {
            AuthSubcommand::Init { name } => cmd_auth_init(name),
            AuthSubcommand::Connect {
                endpoint,
                label,
                vault_alias,
            } => cmd_auth_connect(&endpoint, &label, &vault_alias).await,
            AuthSubcommand::Login => cmd_auth_login(),
            AuthSubcommand::Logout => cmd_auth_logout(),
            AuthSubcommand::Status => cmd_auth_status(),
        },
        crate::Commands::Device { sub } => match sub {
            DeviceSubcommand::List => cmd_device_list(),
            DeviceSubcommand::Revoke { device_id } => cmd_device_revoke(&device_id).await,
        },
        crate::Commands::Vault { sub } => match sub {
            VaultSubcommand::Link { alias } => cmd_vault_link(&alias),
            VaultSubcommand::Unlink => cmd_vault_unlink(),
        },
        crate::Commands::Repo { sub } => cmd_repo(sub).await,
        crate::Commands::Context { sub } => cmd_context(sub).await,
        crate::Commands::Project { sub } => cmd_project(sub).await,
        crate::Commands::Secret { sub } => cmd_secret(sub).await,
        crate::Commands::Migrate { sub } => cmd_migrate(sub).await,
        crate::Commands::Init {
            force,
            operators,
            save_kit,
            hardware_token,
            import_gitignore,
            reader,
            pin,
        } => {
            cmd_init(
                force,
                operators,
                save_kit,
                hardware_token,
                import_gitignore,
                reader,
                pin,
            )
            .await
        }
        crate::Commands::Track {
            paths,
            from_gitignore,
            no_gitignore,
        } => cmd_track(paths, from_gitignore, no_gitignore),
        crate::Commands::Untrack { paths } => cmd_untrack(paths),
        crate::Commands::Status { json, overview } => cmd_status(json, overview),
        crate::Commands::Push {
            message,
            touch,
            local,
            anchor,
            reader,
            pin,
            concurrency,
            replicas,
        } => {
            cmd_push(
                message,
                touch,
                local,
                anchor,
                reader,
                pin,
                concurrency,
                replicas,
            )
            .await
        }
        crate::Commands::History => cmd_history(),
        crate::Commands::Prune {
            keep_last,
            keep_days,
            dry_run,
        } => cmd_prune(keep_last, keep_days, dry_run),
        crate::Commands::Rekey { check, warn_days } => cmd_rekey(check, warn_days),
        crate::Commands::Restore {
            snapshot,
            to,
            dry_run,
            hardware_token,
            reader,
            pin,
        } => cmd_restore(snapshot, to, hardware_token, reader, pin, dry_run),
        crate::Commands::Recover {
            kit,
            shares,
            to,
            require_approval,
            approver_key,
            force,
        } => cmd_recover(kit, shares, to, require_approval, approver_key, force).await,
        crate::Commands::Recovery { sub } => match sub {
            RecoverySubcommand::Export => cmd_recovery_export(),
            RecoverySubcommand::Split {
                threshold,
                shares,
                kit,
                out_dir,
            } => cmd_recovery_split(threshold, shares, kit, out_dir).await,
            RecoverySubcommand::Test { kit, to } => cmd_recovery_test(kit, to).await,
            RecoverySubcommand::KeyBackup {
                kit,
                share,
                replicas,
            } => cmd_recovery_key_backup(kit, share, replicas).await,
            RecoverySubcommand::KeyRestore {
                locator,
                operator,
                output,
            } => cmd_recovery_key_restore(locator, operator, output).await,
        },
        crate::Commands::Token { sub } => cmd_token(sub).await,
        crate::Commands::Anchor {
            head,
            daemon,
            interval,
        } => {
            if daemon {
                println!(
                    "{}",
                    "=======================================================".cyan()
                );
                println!(
                    "{}",
                    "  CipherChain Sovereign Periodic Anchoring Daemon"
                        .bold()
                        .green()
                );
                println!("  Check Interval:  {}s", interval);
                println!("  Target Network:  CipherChain (sovereign PoA ledger)");
                println!(
                    "{}",
                    "=======================================================".cyan()
                );

                // Run initial anchor check immediately
                println!(
                    "[{}] Executing initial CipherChain anchor check...",
                    chrono::Utc::now().to_rfc3339()
                );
                if let Err(e) = cmd_anchor(head.clone()).await {
                    eprintln!("Notice: Initial anchor check: {}", e);
                }

                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            println!("\nShutdown signal received. Exiting anchoring daemon gracefully.");
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {
                            println!(
                                "[{}] Executing periodic CipherChain anchor check...",
                                chrono::Utc::now().to_rfc3339()
                            );
                            if let Err(e) = cmd_anchor(head.clone()).await {
                                eprintln!("Notice: Periodic anchor check: {}", e);
                            }
                        }
                    }
                }
                Ok(())
            } else {
                cmd_anchor(head).await
            }
        }
        crate::Commands::VerifyAnchor { head } => cmd_verify_anchor(head).await,
        crate::Commands::PublishPublicFeed { output, network } => {
            crate::cmd_publish_public_feed(output, network)
        }
        crate::Commands::Hook { sub } => match sub {
            HookSubcommand::Install => cmd_hook_install(),
            HookSubcommand::Check { deep, fix, json } => cmd_hook_check(deep, fix, json),
        },
        crate::Commands::Audit {
            operators,
            export_inventory,
            operator_pin,
            recovery_drill,
        } => cmd_audit(operators, export_inventory, operator_pin, recovery_drill).await,
        crate::Commands::Repair {
            operators,
            replicas,
        } => cmd_repair(operators, replicas).await,
        crate::Commands::Ui {
            host,
            port,
            no_browser,
            local,
            serve,
            url,
        } => crate::cmd_ui(host, port, no_browser, local, serve, url).await,
        crate::Commands::Tui { poll_ms } => crate::tui::run_tui(poll_ms).await,
        crate::Commands::Watch {
            debounce,
            sync,
            dry_run,
        } => crate::cmd_watch(debounce, sync, dry_run).await,
        crate::Commands::Run {
            snapshot,
            env_file,
            project,
            env,
            endpoint,
            token,
            legacy,
            revision,
            no_inherit,
            dry_run,
            quiet,
            json,
            set,
            command,
        } => {
            cmd_run(
                snapshot, env_file, project, env, endpoint, token, legacy, revision, no_inherit,
                dry_run, quiet, json, set, command,
            )
            .await
        }
        crate::Commands::Diff {
            snapshot_a,
            snapshot_b,
            file,
            reveal,
            json,
        } => crate::cmd_diff(snapshot_a, snapshot_b, file, reveal, json),
        crate::Commands::Pull { dry_run, force } => cmd_pull(dry_run, force).await,
        crate::Commands::Completions { shell } => {
            crate::cmd_completions(shell);
            Ok(())
        }
        crate::Commands::Peers { discover, mesh } => cmd_peers(discover, mesh).await,
        crate::Commands::Lease { sub } => match sub {
            LeaseSubcommand::Create {
                closure,
                bytes,
                term_days,
                operator,
            } => crate::cmd_lease_create(closure, bytes, term_days, operator).await,
            LeaseSubcommand::Renew {
                lease_id,
                days,
                bytes,
                operator,
            } => crate::cmd_lease_renew(lease_id, days, bytes, operator).await,
            LeaseSubcommand::List { limit, operator } => {
                crate::cmd_lease_list(limit, operator).await
            }
        },
        crate::Commands::Voucher { sub } => match sub {
            VoucherSubcommand::Issue {
                holder_pk,
                quota,
                ttl,
                operator,
            } => crate::cmd_voucher_issue(holder_pk, quota, ttl, operator).await,
        },
        crate::Commands::Invite { sub } => match sub {
            InviteSubcommand::Pubkey { fleet_key_file } => cmd_invite_pubkey(fleet_key_file),
            InviteSubcommand::Issue {
                node_pk,
                keys_file,
                ttl,
                fleet_key_file,
                out,
            } => cmd_invite_issue(node_pk, keys_file, ttl, fleet_key_file, out),
            InviteSubcommand::Join { ticket, node, via } => {
                cmd_invite_join(ticket, node, via).await
            }
            InviteSubcommand::Refresh { node, via } => cmd_invite_refresh(node, via).await,
            InviteSubcommand::Request { node_pk, ttl, out } => {
                cmd_invite_request(node_pk, ttl, out)
            }
            InviteSubcommand::Approve {
                request,
                fleet_key_file,
                out,
            } => cmd_invite_approve(request, fleet_key_file, out),
            InviteSubcommand::Combine {
                request,
                approval,
                out,
            } => cmd_invite_combine(request, approval, out),
            InviteSubcommand::Verify {
                ticket,
                fleet_keys,
                quorum_k,
            } => cmd_invite_verify(ticket, fleet_keys, quorum_k),
        },
        crate::Commands::Node { sub } => match sub {
            NodeSubcommand::Setup {
                name,
                data_dir,
                port,
                yes,
                join_ticket,
                no_start,
                p2p,
                p2p_bootstrap,
                p2p_tcp_port,
                p2p_quic_port,
            } => {
                cmd_node_setup(
                    name,
                    data_dir,
                    port,
                    yes,
                    join_ticket,
                    no_start,
                    NodeP2pOptions {
                        enabled: p2p,
                        bootstrap: p2p_bootstrap,
                        tcp_port: p2p_tcp_port,
                        quic_port: p2p_quic_port,
                    },
                )
                .await
            }
            NodeSubcommand::Start { data_dir } => cmd_node_start(data_dir).await,
            NodeSubcommand::Status { data_dir } => cmd_node_status(data_dir).await,
            NodeSubcommand::Stop { data_dir } => cmd_node_stop(data_dir).await,
            NodeSubcommand::Backup { data_dir, to } => cmd_node_backup(data_dir, to),
            NodeSubcommand::Standing { data_dir } => cmd_node_standing(data_dir).await,
            NodeSubcommand::P2pInfo { data_dir } => cmd_node_p2p_info(data_dir).await,
        },
        crate::Commands::Approve { sub } => match sub {
            ApproveSubcommand::List => cmd_approve_list().await,
            ApproveSubcommand::Sign { challenge_id, name } => {
                cmd_approve_sign(challenge_id, name).await
            }
            ApproveSubcommand::Status { challenge_id } => cmd_approve_status(challenge_id).await,
        },
        crate::Commands::Doctor { json } => cmd_doctor(json).await,
    }
}
