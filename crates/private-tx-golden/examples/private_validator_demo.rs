//! Runs the private validator PoC flow with the golden-rs adapter.
//!
//! The default output is compact `key=value` data. `--narrated` prints a staged presenter flow,
//! `--pause` waits between narrated stages, `--interactive` lets the presenter choose audit-party
//! behavior, and `--json` emits machine-readable metrics for slides.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::time::Instant;

use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordAssociatedData, ArchiveRecordKey, AuditCoordinator,
    AuditRequest, AuditTransportPublicKey, AuditTransportSecret, AuditorId, ChainId,
    DecryptionResponse, EncryptedPrivateTxPayload, EncryptedPrivateTxRecord,
    InMemoryAuditCoordinator, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
    SubmissionEncryptionAssociatedData, SubmissionPayloadAssociatedData, ThresholdRecordEncryptor,
    ThresholdShareCombiner, ThresholdShareProducer, ThresholdShareVerifier, ValidatorId,
    ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare, ViewingPartyId,
    ViewingPartyPublicShare, ViewingPolicy, archive_associated_data,
    archive_associated_data_for_record, decrypt_submission_payload, encrypt_submission_payload,
    open_private_tx_record, private_tx_record_identity, seal_private_tx_record,
    submission_associated_data_for_encryption, submission_associated_data_for_payload,
};
use miden_node_private_tx_golden::{
    GOLDEN_THRESHOLD_SCHEME_ID, GoldenThresholdAdapter, decrypt_private_tx_archive_record,
};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};

const PRIVATE_NOTE: &str =
    "private note: invoice INV-042, account A -> account B, amount 42, memo medical supplies";
const DEMO_START_BLOCK: u64 = 100;
const AUDIT_DEADLINE_BLOCK: u64 = 106;
const BOND_AMOUNT: u64 = 100;
const SLASH_AMOUNT: u64 = 10;

type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

fn private_payload() -> &'static [u8] {
    PRIVATE_NOTE.as_bytes()
}

fn main() -> DemoResult<()> {
    let options = DemoOptions::parse(env::args().skip(1))?;
    if options.help {
        print_help();
        return Ok(());
    }

    let mut narrator =
        Narrator::new(options.narrated, options.pause, options.use_color(), options.stage_count());
    narrator.intro()?;
    let report = run_demo(&options, &mut narrator)?;

    if options.json {
        print_json(&report);
    } else if !options.narrated {
        print_compact(&report);
    } else {
        narrator.finish(report.total_ms);
    }

    Ok(())
}

#[derive(Default)]
struct DemoOptions {
    narrated: bool,
    pause: bool,
    interactive: bool,
    scenario: Option<InteractiveScenario>,
    json: bool,
    help: bool,
    color_mode: ColorMode,
}

impl DemoOptions {
    fn parse(args: impl IntoIterator<Item = String>) -> DemoResult<Self> {
        let mut options = Self::default();
        for arg in args {
            match arg.as_str() {
                "--narrated" => options.narrated = true,
                "--pause" => {
                    options.narrated = true;
                    options.pause = true;
                },
                "--interactive" => {
                    options.narrated = true;
                    options.interactive = true;
                },
                "--json" => options.json = true,
                "--no-color" | "--color=never" => options.color_mode = ColorMode::Never,
                "--color=always" => options.color_mode = ColorMode::Always,
                "--color=auto" => options.color_mode = ColorMode::Auto,
                "--help" | "-h" => options.help = true,
                other if other.starts_with("--scenario=") => {
                    options.narrated = true;
                    options.interactive = true;
                    options.scenario =
                        Some(InteractiveScenario::parse(other.trim_start_matches("--scenario="))?);
                },
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        if options.help {
            return Ok(options);
        }
        if options.json && options.pause {
            return Err("--json cannot be combined with --pause".into());
        }
        if options.json && options.interactive {
            return Err("--json cannot be combined with --interactive".into());
        }
        if options.json && options.narrated {
            return Err("--json cannot be combined with --narrated".into());
        }

        Ok(options)
    }

    const fn include_coordination(&self) -> bool {
        self.narrated || self.json || self.interactive
    }

    const fn stage_count(&self) -> usize {
        if self.interactive { 6 } else { 7 }
    }

    fn use_color(&self) -> bool {
        match self.color_mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none(),
        }
    }
}

#[derive(Clone, Copy, Default)]
enum ColorMode {
    Always,
    Never,
    #[default]
    Auto,
}

#[derive(Clone, Copy)]
enum InteractiveScenario {
    AllRespond,
    MissingParty(usize),
    BelowThreshold,
}

impl InteractiveScenario {
    fn parse(input: &str) -> DemoResult<Self> {
        match input {
            "all" | "all-respond" => Ok(Self::AllRespond),
            "one-missing" | "missing-one" | "non-responder" => Ok(Self::MissingParty(2)),
            "party-1-missing" | "party-1" | "1" => Ok(Self::MissingParty(0)),
            "party-2-missing" | "party-2" | "2" => Ok(Self::MissingParty(1)),
            "party-3-missing" | "party-3" | "3" => Ok(Self::MissingParty(2)),
            "below-threshold" | "threshold-fail" => Ok(Self::BelowThreshold),
            other => {
                Err(format!("unknown scenario `{other}`; use all, one-missing, or below-threshold")
                    .into())
            },
        }
    }
}

fn print_help() {
    println!("private_validator_demo");
    println!();
    println!("Usage:");
    println!("  cargo run -p miden-node-private-tx-golden --example private_validator_demo");
    println!(
        "  cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --narrated"
    );
    println!(
        "  cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --narrated --pause"
    );
    println!(
        "  cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --interactive"
    );
    println!(
        "  cargo run -p miden-node-private-tx-golden --example private_validator_demo -- --json"
    );
    println!();
    println!("Options:");
    println!("  --narrated  Print staged presenter output.");
    println!("  --pause     Wait for Enter between narrated stages.");
    println!("  --interactive");
    println!("              Prompt for audit-party behavior during the demo.");
    println!("  --scenario=all|one-missing|below-threshold");
    println!("              Script an interactive audit scenario.");
    println!("  --json      Print machine-readable metrics.");
    println!("  --no-color  Disable ANSI color in narrated output.");
    println!("  --color=always|auto|never");
    println!("              Control ANSI color in narrated output.");
}

struct Narrator {
    enabled: bool,
    pause: bool,
    color: bool,
    step: usize,
    total_steps: usize,
}

impl Narrator {
    const fn new(enabled: bool, pause: bool, color: bool, total_steps: usize) -> Self {
        Self {
            enabled,
            pause,
            color,
            step: 0,
            total_steps,
        }
    }

    fn intro(&self) -> DemoResult<()> {
        if !self.enabled {
            return Ok(());
        }

        println!("{}", self.paint("1;36", "Private validator demo"));
        println!(
            "{}",
            self.paint(
                "2",
                "Feasibility PoC: real crypto end to end, with TEE and L1 contracts scoped."
            )
        );
        if self.pause {
            self.wait_for_enter()?;
        }

        Ok(())
    }

    fn stage(&mut self, title: &str, summary: &str, lines: &[String]) -> DemoResult<()> {
        if !self.enabled {
            return Ok(());
        }

        self.step += 1;
        println!();
        println!(
            "{} {}",
            self.paint("1;36", &format!("[{}/{}]", self.step, self.total_steps)),
            self.paint("1", title)
        );
        println!("      {}", self.paint("2", summary));
        for line in lines {
            if line.is_empty() {
                println!();
            } else if let Some(line) = line.strip_prefix('|') {
                println!("        {line}");
            } else {
                println!("      - {line}");
            }
        }

        if self.pause && self.step < self.total_steps {
            self.wait_for_enter()?;
        }

        Ok(())
    }

    fn finish(&self, total_ms: u128) {
        println!();
        println!(
            "{} {}",
            self.paint("1;32", "result=ok"),
            self.paint("2", &format!("total_ms={total_ms}"))
        );
    }

    fn wait_for_enter(&self) -> DemoResult<()> {
        print!("      {}", self.paint("2", "press Enter to continue..."));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(())
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn prompt_interactive_scenario(&self) -> DemoResult<InteractiveScenario> {
        println!();
        println!("{}", self.paint("1;33", "Choose audit-party behavior"));
        println!("      1) everyone responds");
        println!("      2) one party skips the request; audit still has quorum");
        println!("      3) two parties skip the request; audit falls below threshold");

        loop {
            print!("      selection> ");
            io::stdout().flush()?;
            let mut input = String::new();
            if io::stdin().read_line(&mut input)? == 0 {
                return Err("no interactive scenario selected".into());
            }

            match input.trim() {
                "1" => return Ok(InteractiveScenario::AllRespond),
                "2" => return Ok(InteractiveScenario::MissingParty(2)),
                "3" => return Ok(InteractiveScenario::BelowThreshold),
                _ => {
                    println!("      {}", self.paint("31", "pick 1, 2, or 3"));
                },
            }
        }
    }
}

struct DemoReport {
    participants: usize,
    threshold: u16,
    submission_payload_bytes: usize,
    archive_record_bytes: usize,
    archive_ciphertext_bytes: usize,
    wrapped_key_bytes: usize,
    audit_responses_count: usize,
    audit_response_bytes_total: usize,
    dkg_ms: u128,
    client_encrypt_ms: u128,
    validator_archive_ms: u128,
    audit_decrypt_ms: u128,
    coordination: Option<CoordinationReport>,
    total_ms: u128,
}

impl DemoReport {
    const fn audit_response_bytes_avg(&self) -> usize {
        self.audit_response_bytes_total / self.audit_responses_count
    }
}

struct CoordinationReport {
    happy_responded_count: usize,
    happy_slashed_count: usize,
    happy_bonds_unchanged: bool,
    slash_responded_count: usize,
    slash_slashed_count: usize,
    slash_party: String,
    slash_amount: u64,
    slash_bond_before: u64,
    slash_bond_after: u64,
}

fn run_demo(options: &DemoOptions, narrator: &mut Narrator) -> DemoResult<DemoReport> {
    let demo_started = Instant::now();
    let fixture = Fixture::new()?;
    let adapter = GoldenThresholdAdapter;

    let dkg_started = Instant::now();
    let viewing_group = ViewingGroup::setup(&adapter, &fixture.viewing_policy)?;
    let dkg_duration = dkg_started.elapsed();
    let mut dkg_lines = threshold_setup_panel(&viewing_group);
    dkg_lines.extend([
        format!(
            "viewing group: {} parties, threshold {}",
            viewing_group.key_shares.len(),
            viewing_group.threshold
        ),
        "scheme: golden-rs vetKeys over adapter-owned wire bytes".to_string(),
        format!("dkg_ms={}", dkg_duration.as_millis()),
    ]);
    narrator.stage(
        "Set up threshold viewing group",
        "Three viewing parties run DKG once. Later, any two of them can help unlock one audited transaction.",
        &dkg_lines,
    )?;

    let client_started = Instant::now();
    let wire_payload = client_encrypts_private_payload(&fixture)?;
    let client_duration = client_started.elapsed();
    let mut client_lines = client_seal_panel(wire_payload.len());
    client_lines.extend([
        format!("submission_payload_bytes={}", wire_payload.len()),
        "context binding: ciphertext is tied to chain_id + tx_id + validator_id + key_id"
            .to_string(),
        format!("client_encrypt_ms={}", client_duration.as_millis()),
    ]);
    narrator.stage(
        "Client encrypted private payload",
        "The client puts the private note in a sealed envelope for the validator. RPC forwards the envelope but cannot read it.",
        &client_lines,
    )?;

    let validator_started = Instant::now();
    let archive = validator_decrypts_and_archives(
        &fixture,
        &adapter,
        &viewing_group.group_public_key,
        &wire_payload,
    )?;
    let validator_duration = validator_started.elapsed();
    let mut validator_lines = validator_archive_panel(
        &viewing_group,
        archive.record.record_ciphertext.len(),
        archive.wrapped_key_bytes,
    );
    validator_lines.extend([
        format!("validator opened: {PRIVATE_NOTE}"),
        format!("archive_record_bytes={}", archive.record.to_bytes().len()),
        format!(
            "archive_ciphertext_bytes={} (sealed PrivateTxRecord only; wrapped key is separate)",
            archive.record.record_ciphertext.len()
        ),
        "record key: fresh per-transaction K_tx".to_string(),
        format!("threshold-wrapped K_tx bytes={}", archive.wrapped_key_bytes),
        format!("validator_archive_ms={}", validator_duration.as_millis()),
    ]);
    narrator.stage(
        "Validator decrypted and archived private record",
        "The validator opens the envelope inside its trust boundary, then stores a second sealed box for future audit.",
        &validator_lines,
    )?;

    let mut audit_request_lines = audit_request_panel(&fixture, &viewing_group, &archive.record);
    audit_request_lines.extend([
        format!("tx_id={}", short_id(&fixture.tx_id.to_string())),
        format!(
            "archive fetch: {} bytes returned, still sealed",
            archive.record.to_bytes().len()
        ),
        "parties answer only for this transaction identity".to_string(),
    ]);
    narrator.stage(
        "Auditor requests this transaction archive",
        "Audits are explicit per-tx requests, not standing decryption capability.",
        &audit_request_lines,
    )?;

    let audit_started = Instant::now();
    let audit = decrypt_private_tx_archive_record(
        &archive.record,
        viewing_group.threshold,
        &viewing_group.key_shares,
        &viewing_group.public_shares,
    )?;
    let audit_duration = audit_started.elapsed();

    let expected = expected_private_tx_record(&fixture, private_payload().to_vec());
    assert_eq!(audit.record, expected);
    let (audit_title, audit_summary) = if options.interactive {
        (
            "Baseline audit recovery with quorum",
            "This baseline shows that two valid responses can open the archive. The next step applies your selected party behavior.",
        )
    } else {
        (
            "Auditor recovered one archived transaction",
            "The auditor does not get a standing key. Enough parties answer this request, so the auditor recovers K_tx and opens the archive.",
        )
    };
    let mut audit_lines = audit_recovery_panel(&viewing_group);
    audit_lines.extend([
        format!("auditor opened: {PRIVATE_NOTE}"),
        format!("responses={}/{}", audit.response_count, viewing_group.key_shares.len()),
        format!("audit_response_bytes_total={}", audit.response_bytes_total),
        format!("audit_response_bytes_avg={}", audit.response_bytes_total / audit.response_count),
        format!("audit_decrypt_ms={}", audit_duration.as_millis()),
    ]);
    narrator.stage(audit_title, audit_summary, &audit_lines)?;

    let coordination = if options.interactive {
        let scenario = match options.scenario {
            Some(scenario) => scenario,
            None => narrator.prompt_interactive_scenario()?,
        };
        let outcome = run_interactive_coordination_scenario(
            &adapter,
            &viewing_group,
            &archive.record,
            &expected,
            scenario,
        )?;
        narrator.stage(
            "Interactive audit coordination outcome",
            &outcome.summary,
            &outcome.lines,
        )?;
        None
    } else if options.include_coordination() {
        let coordination =
            run_coordination_scenarios(&adapter, &viewing_group, &archive.record, &expected)?;
        let all_responder_indices = (0..viewing_group.key_shares.len()).collect::<Vec<_>>();
        let mut happy_lines = coordination_panel(&viewing_group, &all_responder_indices);
        happy_lines.extend([
            format!(
                "responded={}/{}",
                coordination.happy_responded_count,
                viewing_group.key_shares.len()
            ),
            format!("slashed={}", coordination.happy_slashed_count),
            format!("bonds_unchanged={}", coordination.happy_bonds_unchanged),
            format!("settlement ledger: all party bonds remain {BOND_AMOUNT}"),
        ]);
        narrator.stage(
            "Audit coordination happy path",
            "The coordinator records every response before the deadline, so the request settles with no bond changes.",
            &happy_lines,
        )?;
        let missed_responder_indices = responder_indices(
            viewing_group.key_shares.len(),
            InteractiveScenario::MissingParty(viewing_group.key_shares.len() - 1),
        );
        let mut missed_lines = coordination_panel(&viewing_group, &missed_responder_indices);
        missed_lines.extend([
            format!(
                "responded={}/{}",
                coordination.slash_responded_count,
                viewing_group.key_shares.len()
            ),
            format!("slashed={}", coordination.slash_slashed_count),
            format!("slashed_party={}", coordination.slash_party),
            format!("bond={} -> {}", coordination.slash_bond_before, coordination.slash_bond_after),
            format!(
                "settlement ledger: {} loses {} mock bond",
                coordination.slash_party, coordination.slash_amount
            ),
            "scope: slashing covers non-submission; invalid-response fraud proofs are v2"
                .to_string(),
        ]);
        narrator.stage(
            "Audit coordination missed response",
            "The audit still has enough responses to open the record, but the missing party loses mock bond balance.",
            &missed_lines,
        )?;
        Some(coordination)
    } else {
        None
    };

    Ok(DemoReport {
        participants: viewing_group.key_shares.len(),
        threshold: viewing_group.threshold,
        submission_payload_bytes: wire_payload.len(),
        archive_record_bytes: archive.record.to_bytes().len(),
        archive_ciphertext_bytes: archive.record.record_ciphertext.len(),
        wrapped_key_bytes: archive.wrapped_key_bytes,
        audit_responses_count: audit.response_count,
        audit_response_bytes_total: audit.response_bytes_total,
        dkg_ms: dkg_duration.as_millis(),
        client_encrypt_ms: client_duration.as_millis(),
        validator_archive_ms: validator_duration.as_millis(),
        audit_decrypt_ms: audit_duration.as_millis(),
        coordination,
        total_ms: demo_started.elapsed().as_millis(),
    })
}

fn print_compact(report: &DemoReport) {
    println!("private validator golden-rs demo");
    println!("participants={} threshold={}", report.participants, report.threshold);
    println!("submission_payload_bytes={}", report.submission_payload_bytes);
    println!("archive_record_bytes={}", report.archive_record_bytes);
    println!("archive_ciphertext_bytes={}", report.archive_ciphertext_bytes);
    println!("wrapped_key_bytes={}", report.wrapped_key_bytes);
    println!("audit_responses_count={}", report.audit_responses_count);
    println!("audit_response_bytes_total={}", report.audit_response_bytes_total);
    println!("audit_response_bytes_avg={}", report.audit_response_bytes_avg());
    println!("dkg_ms={}", report.dkg_ms);
    println!("client_encrypt_ms={}", report.client_encrypt_ms);
    println!("validator_archive_ms={}", report.validator_archive_ms);
    println!("audit_decrypt_ms={}", report.audit_decrypt_ms);
    println!("total_ms={}", report.total_ms);
}

fn print_json(report: &DemoReport) {
    println!("{{");
    println!("  \"participants\": {},", report.participants);
    println!("  \"threshold\": {},", report.threshold);
    println!("  \"submission_payload_bytes\": {},", report.submission_payload_bytes);
    println!("  \"archive_record_bytes\": {},", report.archive_record_bytes);
    println!("  \"archive_ciphertext_bytes\": {},", report.archive_ciphertext_bytes);
    println!("  \"wrapped_key_bytes\": {},", report.wrapped_key_bytes);
    println!("  \"audit_responses_count\": {},", report.audit_responses_count);
    println!("  \"audit_response_bytes_total\": {},", report.audit_response_bytes_total);
    println!("  \"audit_response_bytes_avg\": {},", report.audit_response_bytes_avg());
    println!("  \"dkg_ms\": {},", report.dkg_ms);
    println!("  \"client_encrypt_ms\": {},", report.client_encrypt_ms);
    println!("  \"validator_archive_ms\": {},", report.validator_archive_ms);
    println!("  \"audit_decrypt_ms\": {},", report.audit_decrypt_ms);
    if let Some(coordination) = &report.coordination {
        println!("  \"coordination\": {{");
        println!("    \"happy_responded_count\": {},", coordination.happy_responded_count);
        println!("    \"happy_slashed_count\": {},", coordination.happy_slashed_count);
        println!("    \"happy_bonds_unchanged\": {},", coordination.happy_bonds_unchanged);
        println!("    \"slash_responded_count\": {},", coordination.slash_responded_count);
        println!("    \"slash_slashed_count\": {},", coordination.slash_slashed_count);
        println!("    \"slash_party\": \"{}\",", json_escape(&coordination.slash_party));
        println!("    \"slash_amount\": {},", coordination.slash_amount);
        println!("    \"slash_bond_before\": {},", coordination.slash_bond_before);
        println!("    \"slash_bond_after\": {}", coordination.slash_bond_after);
        println!("  }},");
    } else {
        println!("  \"coordination\": null,");
    }
    println!("  \"total_ms\": {}", report.total_ms);
    println!("}}");
}

fn json_escape(input: &str) -> String {
    let mut output = String::new();
    for character in input.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            },
            character => output.push(character),
        }
    }

    output
}

fn short_id(id: &str) -> String {
    const PREFIX_LEN: usize = 18;
    if id.len() <= PREFIX_LEN {
        id.to_string()
    } else {
        format!("{}...", &id[..PREFIX_LEN])
    }
}

fn sealed_box(bytes: usize) -> String {
    let width = (bytes / 32).clamp(4, 14);
    format!("[{}]", "#".repeat(width))
}

fn diagram(line: impl Into<String>) -> String {
    format!("|{}", line.into())
}

fn diagram_blank() -> String {
    String::new()
}

fn party_names(viewing_group: &ViewingGroup) -> Vec<String> {
    viewing_group
        .key_shares
        .iter()
        .map(|share| share.party_id.to_string())
        .collect::<Vec<_>>()
}

fn threshold_setup_panel(viewing_group: &ViewingGroup) -> Vec<String> {
    let parties = party_names(viewing_group);
    vec![
        diagram("VIEWING GROUP"),
        diagram(format!("  [{}]", parties.join("]  ["))),
        diagram(format!(
            "  unlock rule: any {} responses for one requested tx",
            viewing_group.threshold
        )),
        diagram_blank(),
    ]
}

fn client_seal_panel(payload_bytes: usize) -> Vec<String> {
    vec![
        diagram("CLIENT                              RPC / OPERATOR"),
        diagram("  has private note                   never sees private note"),
        diagram(format!(
            "  private note --seal--> {} encrypted_private_payload ({payload_bytes} bytes)",
            sealed_box(payload_bytes)
        )),
        diagram("                                      forwards opaque bytes"),
        diagram_blank(),
        format!("client view: {PRIVATE_NOTE}"),
        "RPC/operator view: ProvenTransaction + opaque encrypted_private_payload".to_string(),
    ]
}

fn validator_archive_panel(
    viewing_group: &ViewingGroup,
    archive_ciphertext_bytes: usize,
    wrapped_key_bytes: usize,
) -> Vec<String> {
    vec![
        diagram("VALIDATOR TRUST BOUNDARY"),
        diagram("  encrypted_private_payload --open--> private note"),
        diagram("  private note --validate tx--> ok"),
        diagram(format!(
            "  PrivateTxRecord + K_tx --seal--> {} archive ciphertext ({archive_ciphertext_bytes} bytes)",
            sealed_box(archive_ciphertext_bytes)
        )),
        diagram(format!(
            "  K_tx --threshold lock--> need {} of {} parties ({wrapped_key_bytes} bytes)",
            viewing_group.threshold,
            viewing_group.key_shares.len()
        )),
        diagram_blank(),
    ]
}

fn audit_request_panel(
    fixture: &Fixture,
    viewing_group: &ViewingGroup,
    archive_record: &EncryptedPrivateTxRecord,
) -> Vec<String> {
    let parties = party_names(viewing_group).join(", ");
    vec![
        diagram("AUDIT REQUEST"),
        diagram(format!("  auditor asks for tx_id {}", short_id(&fixture.tx_id.to_string()))),
        diagram("  auditor publishes one-time reply key for encrypted responses"),
        diagram(format!(
            "  archive store returns {} sealed bytes; private note is still hidden",
            archive_record.to_bytes().len()
        )),
        diagram(format!("  request goes to: {parties}")),
        diagram_blank(),
        "auditor view: tx_id + reply key + sealed archive; no private note yet".to_string(),
    ]
}

fn audit_recovery_panel(viewing_group: &ViewingGroup) -> Vec<String> {
    let threshold = usize::from(viewing_group.threshold);
    let responding_parties = viewing_group
        .key_shares
        .iter()
        .take(threshold)
        .map(|share| share.party_id.to_string())
        .collect::<Vec<_>>();
    let unused_parties = viewing_group
        .key_shares
        .iter()
        .skip(threshold)
        .map(|share| share.party_id.to_string())
        .collect::<Vec<_>>();
    let unused_line = if unused_parties.is_empty() {
        "  no extra parties in this demo group".to_string()
    } else {
        format!("  not needed for this audit: {}", unused_parties.join(", "))
    };

    vec![
        diagram("THRESHOLD UNLOCK"),
        diagram(format!("  responses: [{}]", responding_parties.join("] + ["))),
        diagram(format!("  {} responses -> K_tx", viewing_group.threshold)),
        diagram("  archive ciphertext + K_tx -> private note"),
        diagram(unused_line),
        diagram_blank(),
    ]
}

fn coordination_panel(viewing_group: &ViewingGroup, responder_indices: &[usize]) -> Vec<String> {
    vec![
        diagram("COORDINATION LEDGER"),
        diagram(response_row(viewing_group, responder_indices)),
        diagram(format!("  before bonds: {}", bond_row(viewing_group, |_| BOND_AMOUNT))),
        diagram(format!(
            "  after settlement: {}",
            bond_row(viewing_group, |index| {
                if responder_indices.contains(&index) {
                    BOND_AMOUNT
                } else {
                    BOND_AMOUNT.saturating_sub(SLASH_AMOUNT)
                }
            })
        )),
        diagram_blank(),
    ]
}

fn response_row(viewing_group: &ViewingGroup, responder_indices: &[usize]) -> String {
    let responses = viewing_group
        .key_shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            let status = if responder_indices.contains(&index) {
                "response"
            } else {
                "missed"
            };
            format!("{}: {status}", share.party_id)
        })
        .collect::<Vec<_>>()
        .join("] [");
    let verdict = if responder_indices.len() >= usize::from(viewing_group.threshold) {
        "quorum reached"
    } else {
        "below threshold"
    };

    format!(
        "  responses: [{responses}] -> {}/{} submitted, need {} ({verdict})",
        responder_indices.len(),
        viewing_group.key_shares.len(),
        viewing_group.threshold
    )
}

fn bond_row(viewing_group: &ViewingGroup, balance_for_index: impl Fn(usize) -> u64) -> String {
    viewing_group
        .key_shares
        .iter()
        .enumerate()
        .map(|(index, share)| format!("{}={}", share.party_id, balance_for_index(index)))
        .collect::<Vec<_>>()
        .join("  ")
}

struct Fixture {
    chain_id: ChainId,
    tx_id: TransactionId,
    validator_id: ValidatorId,
    validator_encryption_key_id: Word,
    tee_attestation_id: Word,
    public_tx_hash: Word,
    sealing_key: SealingKey,
    unsealing_key: UnsealingKey,
    viewing_policy: ViewingPolicy,
}

impl Fixture {
    fn new() -> DemoResult<Self> {
        let validator_secret_key = SecretKey::new();
        let validator_public_key = validator_secret_key.public_key();
        let validator_public_key_bytes = validator_public_key.to_bytes();
        let mut attestation_bytes = Vec::new();
        attestation_bytes.extend_from_slice(b"demo-attestation");
        attestation_bytes.extend_from_slice(&validator_public_key_bytes);

        Ok(Self {
            chain_id: ChainId::new("miden-devnet")?,
            tx_id: tx_id(100)?,
            validator_id: ValidatorId::new("validator-1")?,
            validator_encryption_key_id: word(20),
            tee_attestation_id: Hasher::hash(&attestation_bytes),
            public_tx_hash: Hasher::hash(b"demo-public-proven-transaction"),
            sealing_key: SealingKey::X25519XChaCha20Poly1305(validator_public_key),
            unsealing_key: UnsealingKey::X25519XChaCha20Poly1305(validator_secret_key),
            viewing_policy: ViewingPolicy {
                version: PRIVATE_TX_VERSION,
                viewing_group_id: word(200),
                threshold: 2,
                parties: vec![
                    ViewingPartyId::new("party-1")?,
                    ViewingPartyId::new("party-2")?,
                    ViewingPartyId::new("party-3")?,
                ],
                scheme_id: GOLDEN_THRESHOLD_SCHEME_ID,
            },
        })
    }
}

struct ViewingGroup {
    threshold: u16,
    group_public_key: ViewingGroupPublicKey,
    key_shares: Vec<ViewingKeyShare>,
    public_shares: Vec<ViewingPartyPublicShare>,
}

impl ViewingGroup {
    fn setup(adapter: &GoldenThresholdAdapter, policy: &ViewingPolicy) -> DemoResult<Self> {
        let local_participants = policy
            .parties
            .iter()
            .enumerate()
            .map(|(index, party_id)| {
                GoldenThresholdAdapter::generate_local_participant(
                    party_id.clone(),
                    u32::try_from(index + 1).expect("demo participant index fits in u32"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let session = GoldenThresholdAdapter::dkg_session(
            policy.viewing_group_id,
            policy.threshold,
            local_participants
                .iter()
                .map(|participant| participant.public.clone())
                .collect(),
        )?;
        let dealings = local_participants
            .iter()
            .map(|participant| adapter.create_dkg_dealing(&session, participant))
            .collect::<Result<Vec<_>, _>>()?;

        for dealing in &dealings {
            adapter.verify_dkg_dealing(&session, &dealing.public)?;
        }

        let key_shares = local_participants
            .iter()
            .enumerate()
            .map(|(index, participant)| {
                let peer_dealings = dealings
                    .iter()
                    .enumerate()
                    .filter(|(peer_index, _)| *peer_index != index)
                    .map(|(_, dealing)| dealing.public.clone())
                    .collect::<Vec<_>>();
                adapter.complete_dkg(
                    &session,
                    participant,
                    &dealings[index].private,
                    &peer_dealings,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let group_public_key = GoldenThresholdAdapter::viewing_group_public_key(&key_shares[0])?;
        let public_shares = key_shares
            .iter()
            .map(GoldenThresholdAdapter::viewing_party_public_share)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            threshold: policy.threshold,
            group_public_key,
            key_shares,
            public_shares,
        })
    }
}

struct ArchiveOutput {
    record: EncryptedPrivateTxRecord,
    wrapped_key_bytes: usize,
}

fn client_encrypts_private_payload(fixture: &Fixture) -> DemoResult<Vec<u8>> {
    let submission_ad =
        submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
            chain_id: &fixture.chain_id,
            tx_id: fixture.tx_id,
            validator_id: &fixture.validator_id,
            validator_encryption_key_id: fixture.validator_encryption_key_id,
        });

    Ok(encrypt_submission_payload(
        &fixture.sealing_key,
        fixture.validator_encryption_key_id,
        private_payload(),
        &submission_ad,
    )?
    .to_bytes())
}

fn validator_decrypts_and_archives(
    fixture: &Fixture,
    adapter: &GoldenThresholdAdapter,
    group_public_key: &ViewingGroupPublicKey,
    wire_payload: &[u8],
) -> DemoResult<ArchiveOutput> {
    let payload = EncryptedPrivateTxPayload::read_from_bytes(wire_payload)?;
    let submission_ad = submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        validator_id: &fixture.validator_id,
        payload: &payload,
    });
    let private_payload =
        decrypt_submission_payload(&fixture.unsealing_key, &payload, &submission_ad)?;
    let record = expected_private_tx_record(fixture, private_payload);
    let identity = private_tx_record_identity(&fixture.chain_id, fixture.tx_id);
    let archive_ad = archive_associated_data(ArchiveAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        viewing_group_id: group_public_key.viewing_group_id,
        identity: &identity,
        validator_id: &fixture.validator_id,
        validator_encryption_key_id: fixture.validator_encryption_key_id,
        tee_attestation_id: fixture.tee_attestation_id,
    });
    let record_key = ArchiveRecordKey::generate();
    let record_key_bytes = record_key.to_bytes();
    let record_ciphertext = seal_private_tx_record(&record_key, &record.to_bytes(), &archive_ad)?;
    let data_key_protection =
        adapter.encrypt_record_key(group_public_key, &identity, &archive_ad, &record_key_bytes)?;
    let wrapped_key_bytes = data_key_protection.to_bytes().len();

    Ok(ArchiveOutput {
        record: EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            viewing_group_id: group_public_key.viewing_group_id,
            identity,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            record_ciphertext,
            data_key_protection,
        },
        wrapped_key_bytes,
    })
}

struct HappyCoordinationOutput {
    responded_count: usize,
    slashed_count: usize,
    bonds_unchanged: bool,
}

struct SlashCoordinationOutput {
    responded_count: usize,
    slashed_count: usize,
    slashed_party: ViewingPartyId,
    slash_amount: u64,
    bond_before: u64,
    bond_after: u64,
}

struct InteractiveCoordinationOutput {
    summary: String,
    lines: Vec<String>,
}

fn run_coordination_scenarios(
    adapter: &GoldenThresholdAdapter,
    viewing_group: &ViewingGroup,
    encrypted_record: &EncryptedPrivateTxRecord,
    expected_record: &PrivateTxRecord,
) -> DemoResult<CoordinationReport> {
    let happy =
        run_coordination_happy_path(adapter, viewing_group, encrypted_record, expected_record)?;
    let slash =
        run_coordination_slash_path(adapter, viewing_group, encrypted_record, expected_record)?;

    Ok(CoordinationReport {
        happy_responded_count: happy.responded_count,
        happy_slashed_count: happy.slashed_count,
        happy_bonds_unchanged: happy.bonds_unchanged,
        slash_responded_count: slash.responded_count,
        slash_slashed_count: slash.slashed_count,
        slash_party: slash.slashed_party.to_string(),
        slash_amount: slash.slash_amount,
        slash_bond_before: slash.bond_before,
        slash_bond_after: slash.bond_after,
    })
}

fn run_interactive_coordination_scenario(
    adapter: &GoldenThresholdAdapter,
    viewing_group: &ViewingGroup,
    encrypted_record: &EncryptedPrivateTxRecord,
    expected_record: &PrivateTxRecord,
    scenario: InteractiveScenario,
) -> DemoResult<InteractiveCoordinationOutput> {
    let (coordinator, auditor_id) = authorized_coordinator(viewing_group)?;
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let request = audit_request(
        auditor_id,
        encrypted_record,
        viewing_group,
        transport_public_key.clone(),
        AUDIT_DEADLINE_BLOCK,
    );
    let request_id = coordinator.request_audit(request)?;
    let responders = responder_indices(viewing_group.key_shares.len(), scenario);

    submit_audit_responses(
        adapter,
        &coordinator,
        request_id,
        encrypted_record,
        &transport_public_key,
        responders.iter().map(|index| &viewing_group.key_shares[*index]),
    )?;

    let responses = coordinator.fetch_responses(request_id)?;
    let audit_recovered = if responses.responses.len() < usize::from(viewing_group.threshold) {
        false
    } else {
        let record = recover_audit_record_from_responses(
            adapter,
            encrypted_record,
            &responses.responses,
            viewing_group.threshold,
            &transport_public_key,
            &transport_secret,
            &viewing_group.public_shares,
        )?;
        assert_eq!(&record, expected_record);
        true
    };

    coordinator.advance_block(AUDIT_DEADLINE_BLOCK - DEMO_START_BLOCK)?;
    let settlement = coordinator.settle(request_id)?;
    let mut lines = vec![scenario_line(viewing_group, scenario)];
    lines.extend(coordination_panel(viewing_group, &responders));
    lines.push(format!(
        "audit result: {}",
        if audit_recovered {
            "record recovered"
        } else {
            "below threshold, record remains locked"
        }
    ));

    if settlement.slashed_parties.is_empty() {
        lines.push("settlement: no slashing".to_string());
        lines.push(format!("settlement ledger: all party bonds remain {BOND_AMOUNT}"));
    } else {
        lines.push(format!(
            "settlement: {} non-responder(s) slashed",
            settlement.slashed_parties.len()
        ));
        for party in &settlement.slashed_parties {
            let deducted = settlement.slash_amounts.get(party).copied().unwrap_or_default();
            let balance = coordinator.party_bond(party)?;
            lines.push(format!(
                "settlement ledger: {party} bond {BOND_AMOUNT} -> {balance} (-{deducted})"
            ));
        }
    }

    Ok(InteractiveCoordinationOutput {
        summary: "You choose which parties respond; the coordinator settles that exact request."
            .to_string(),
        lines,
    })
}

fn responder_indices(party_count: usize, scenario: InteractiveScenario) -> Vec<usize> {
    match scenario {
        InteractiveScenario::AllRespond => (0..party_count).collect(),
        InteractiveScenario::MissingParty(missing_index) => {
            (0..party_count).filter(|index| *index != missing_index).collect()
        },
        InteractiveScenario::BelowThreshold => vec![0],
    }
}

fn scenario_line(viewing_group: &ViewingGroup, scenario: InteractiveScenario) -> String {
    match scenario {
        InteractiveScenario::AllRespond => "selected behavior: every party responds".to_string(),
        InteractiveScenario::MissingParty(index) => {
            let party = viewing_group
                .key_shares
                .get(index)
                .map(|share| share.party_id.to_string())
                .unwrap_or_else(|| format!("party-{}", index + 1));
            format!("selected behavior: {party} does not respond")
        },
        InteractiveScenario::BelowThreshold => {
            "selected behavior: only party-1 responds, below threshold".to_string()
        },
    }
}

fn run_coordination_happy_path(
    adapter: &GoldenThresholdAdapter,
    viewing_group: &ViewingGroup,
    encrypted_record: &EncryptedPrivateTxRecord,
    expected_record: &PrivateTxRecord,
) -> DemoResult<HappyCoordinationOutput> {
    let (coordinator, auditor_id) = authorized_coordinator(viewing_group)?;
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let request = audit_request(
        auditor_id,
        encrypted_record,
        viewing_group,
        transport_public_key.clone(),
        AUDIT_DEADLINE_BLOCK,
    );
    let request_id = coordinator.request_audit(request)?;

    submit_audit_responses(
        adapter,
        &coordinator,
        request_id,
        encrypted_record,
        &transport_public_key,
        viewing_group.key_shares.iter(),
    )?;

    let responses = coordinator.fetch_responses(request_id)?;
    let recovered_record = recover_audit_record_from_responses(
        adapter,
        encrypted_record,
        &responses.responses,
        viewing_group.threshold,
        &transport_public_key,
        &transport_secret,
        &viewing_group.public_shares,
    )?;
    assert_eq!(&recovered_record, expected_record);

    coordinator.advance_block(AUDIT_DEADLINE_BLOCK - DEMO_START_BLOCK)?;
    let settlement = coordinator.settle(request_id)?;
    let mut bonds_unchanged = true;
    for key_share in &viewing_group.key_shares {
        if coordinator.party_bond(&key_share.party_id)? != BOND_AMOUNT {
            bonds_unchanged = false;
        }
    }

    Ok(HappyCoordinationOutput {
        responded_count: responses.responses.len(),
        slashed_count: settlement.slashed_parties.len(),
        bonds_unchanged,
    })
}

fn run_coordination_slash_path(
    adapter: &GoldenThresholdAdapter,
    viewing_group: &ViewingGroup,
    encrypted_record: &EncryptedPrivateTxRecord,
    expected_record: &PrivateTxRecord,
) -> DemoResult<SlashCoordinationOutput> {
    let (coordinator, auditor_id) = authorized_coordinator(viewing_group)?;
    let missing_share = viewing_group
        .key_shares
        .last()
        .ok_or("demo viewing group must include at least one party")?;
    let missing_party = missing_share.party_id.clone();
    let bond_before = coordinator.party_bond(&missing_party)?;
    let (transport_public_key, transport_secret) =
        GoldenThresholdAdapter::audit_transport_keypair();
    let request = audit_request(
        auditor_id,
        encrypted_record,
        viewing_group,
        transport_public_key.clone(),
        AUDIT_DEADLINE_BLOCK,
    );
    let request_id = coordinator.request_audit(request)?;

    submit_audit_responses(
        adapter,
        &coordinator,
        request_id,
        encrypted_record,
        &transport_public_key,
        viewing_group.key_shares.iter().take(usize::from(viewing_group.threshold)),
    )?;

    let responses = coordinator.fetch_responses(request_id)?;
    let recovered_record = recover_audit_record_from_responses(
        adapter,
        encrypted_record,
        &responses.responses,
        viewing_group.threshold,
        &transport_public_key,
        &transport_secret,
        &viewing_group.public_shares,
    )?;
    assert_eq!(&recovered_record, expected_record);

    coordinator.advance_block(AUDIT_DEADLINE_BLOCK - DEMO_START_BLOCK)?;
    let settlement = coordinator.settle(request_id)?;
    let bond_after = coordinator.party_bond(&missing_party)?;
    let slash_amount = settlement.slash_amounts.get(&missing_party).copied().unwrap_or_default();

    Ok(SlashCoordinationOutput {
        responded_count: responses.responses.len(),
        slashed_count: settlement.slashed_parties.len(),
        slashed_party: missing_party,
        slash_amount,
        bond_before,
        bond_after,
    })
}

fn authorized_coordinator(
    viewing_group: &ViewingGroup,
) -> DemoResult<(InMemoryAuditCoordinator, AuditorId)> {
    let coordinator = InMemoryAuditCoordinator::new(DEMO_START_BLOCK, SLASH_AMOUNT);
    let auditor_id = AuditorId::new("auditor-1")?;
    coordinator.authorize_auditor(auditor_id.clone())?;
    for key_share in &viewing_group.key_shares {
        coordinator.deposit_bond(key_share.party_id.clone(), BOND_AMOUNT)?;
    }

    Ok((coordinator, auditor_id))
}

fn audit_request(
    auditor_id: AuditorId,
    encrypted_record: &EncryptedPrivateTxRecord,
    viewing_group: &ViewingGroup,
    transport_public_key: AuditTransportPublicKey,
    deadline_block: u64,
) -> AuditRequest {
    AuditRequest {
        auditor_id,
        tx_id: encrypted_record.tx_id,
        viewing_group_id: encrypted_record.viewing_group_id,
        identity: encrypted_record.identity.clone(),
        transport_public_key,
        parties: viewing_group.key_shares.iter().map(|share| share.party_id.clone()).collect(),
        deadline_block,
    }
}

fn submit_audit_responses<'a>(
    adapter: &GoldenThresholdAdapter,
    coordinator: &InMemoryAuditCoordinator,
    request_id: miden_node_private_tx::AuditRequestId,
    encrypted_record: &EncryptedPrivateTxRecord,
    transport_public_key: &AuditTransportPublicKey,
    key_shares: impl IntoIterator<Item = &'a ViewingKeyShare>,
) -> DemoResult<()> {
    let archive_ad = archive_associated_data_for_record(ArchiveRecordAssociatedData {
        record: encrypted_record,
    });
    for key_share in key_shares {
        let response = adapter.produce_decryption_response(
            key_share,
            &encrypted_record.identity,
            &archive_ad,
            transport_public_key,
            &encrypted_record.data_key_protection,
        )?;
        coordinator.submit_response(request_id, &key_share.party_id, response)?;
    }

    Ok(())
}

fn recover_audit_record_from_responses(
    adapter: &GoldenThresholdAdapter,
    encrypted_record: &EncryptedPrivateTxRecord,
    responses: &[DecryptionResponse],
    threshold: u16,
    transport_public_key: &AuditTransportPublicKey,
    transport_secret: &AuditTransportSecret,
    public_shares: &[ViewingPartyPublicShare],
) -> DemoResult<PrivateTxRecord> {
    let archive_ad = archive_associated_data_for_record(ArchiveRecordAssociatedData {
        record: encrypted_record,
    });
    for response in responses {
        adapter.verify_decryption_response(
            response,
            &encrypted_record.identity,
            &archive_ad,
            transport_public_key,
            public_share_for(public_shares, &response.party_id)?,
        )?;
    }

    let threshold_response_count = usize::from(threshold);
    let threshold_responses = responses
        .get(..threshold_response_count)
        .ok_or("not enough audit responses to recover record key")?;
    let unlock = adapter.combine_responses(
        &encrypted_record.data_key_protection,
        threshold_responses,
        threshold,
        &encrypted_record.identity,
        &archive_ad,
        transport_secret,
    )?;
    let record_key = ArchiveRecordKey::from_bytes(&unlock.record_key)?;
    let plaintext =
        open_private_tx_record(&record_key, &encrypted_record.record_ciphertext, &archive_ad)?;

    Ok(PrivateTxRecord::read_from_bytes(&plaintext)?)
}

fn public_share_for<'a>(
    public_shares: &'a [ViewingPartyPublicShare],
    party_id: &ViewingPartyId,
) -> DemoResult<&'a ViewingPartyPublicShare> {
    public_shares
        .iter()
        .find(|public_share| &public_share.party_id == party_id)
        .ok_or_else(|| format!("missing public share for {party_id}").into())
}

fn expected_private_tx_record(fixture: &Fixture, transaction_inputs: Vec<u8>) -> PrivateTxRecord {
    PrivateTxRecord::new(
        PrivateTxRecordMetadata {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            public_tx_hash: fixture.public_tx_hash,
        },
        transaction_inputs,
    )
}

fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}

fn tx_id(seed: u32) -> DemoResult<TransactionId> {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).map_err(Into::into)
}
