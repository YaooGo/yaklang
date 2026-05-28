package loop_firmware_analysis

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yaklang/yaklang/common/ai/aid/aicommon"
	"github.com/yaklang/yaklang/common/ai/aid/aicommon/mock"
	"github.com/yaklang/yaklang/common/ai/aid/aireact/reactloops"
	_ "github.com/yaklang/yaklang/common/ai/aid/aireact/reactloops/loopinfra"
	"github.com/yaklang/yaklang/common/schema"
	"github.com/yaklang/yaklang/common/utils"
)

type firmwareFinalizeTimelineRecord struct {
	entry   string
	content string
}

type firmwareFinalizeTestInvoker struct {
	*mock.MockInvoker
	artifactDir     string
	resultPayloads  []string
	timelineRecords []firmwareFinalizeTimelineRecord
	events          []*schema.AiOutputEvent
	mu              sync.Mutex
}

func newFirmwareFinalizeTestInvoker(t *testing.T) *firmwareFinalizeTestInvoker {
	t.Helper()

	invoker := &firmwareFinalizeTestInvoker{
		MockInvoker: mock.NewMockInvoker(context.Background()),
		artifactDir: t.TempDir(),
	}
	if cfg, ok := invoker.GetConfig().(*mock.MockedAIConfig); ok {
		cfg.Emitter = aicommon.NewEmitter("firmware-analysis-finalize-test", func(e *schema.AiOutputEvent) (*schema.AiOutputEvent, error) {
			invoker.mu.Lock()
			defer invoker.mu.Unlock()
			invoker.events = append(invoker.events, e)
			return e, nil
		})
	}
	return invoker
}

func (i *firmwareFinalizeTestInvoker) EmitResultAfterStream(result any) {
	i.mu.Lock()
	i.resultPayloads = append(i.resultPayloads, strings.TrimSpace(utils.InterfaceToString(result)))
	i.mu.Unlock()
	if cfg, ok := i.GetConfig().(*mock.MockedAIConfig); ok && cfg.Emitter != nil {
		_, _ = cfg.Emitter.EmitResultAfterStream("result", result, false)
	}
}

func (i *firmwareFinalizeTestInvoker) EmitFileArtifactWithExt(name, ext string, data any) string {
	name = strings.ReplaceAll(name, string(filepath.Separator), "_")
	return filepath.Join(i.artifactDir, name+ext)
}

func (i *firmwareFinalizeTestInvoker) AddToTimeline(entry, content string) {
	i.mu.Lock()
	i.timelineRecords = append(i.timelineRecords, firmwareFinalizeTimelineRecord{entry: entry, content: content})
	i.mu.Unlock()
}

func newFirmwareFinalizeTestLoop(t *testing.T, invoker *firmwareFinalizeTestInvoker, opts ...reactloops.ReActLoopOption) *reactloops.ReActLoop {
	t.Helper()

	baseOpts := []reactloops.ReActLoopOption{
		reactloops.WithAllowRAG(false),
		reactloops.WithAllowAIForge(false),
		reactloops.WithAllowPlanAndExec(false),
		reactloops.WithAllowToolCall(false),
		reactloops.WithAllowUserInteract(false),
	}
	baseOpts = append(baseOpts, opts...)

	loop, err := reactloops.NewReActLoop("firmware-analysis-finalize-test", invoker, baseOpts...)
	if err != nil {
		t.Fatalf("create loop: %v", err)
	}
	return loop
}

func hasFirmwareTimelineEntry(records []firmwareFinalizeTimelineRecord, key string) bool {
	for _, record := range records {
		if record.entry == key {
			return true
		}
	}
	return false
}

func TestFirmwareAnalysisLoopRegistersMetadata(t *testing.T) {
	meta, ok := reactloops.GetLoopMetadata(LoopFirmwareAnalysisName)
	if !ok {
		t.Fatalf("expected loop %q to be registered", LoopFirmwareAnalysisName)
	}
	if meta.Description == "" {
		t.Fatalf("expected loop %q to have an English description", LoopFirmwareAnalysisName)
	}
	if meta.DescriptionZh == "" {
		t.Fatalf("expected loop %q to have a Chinese description", LoopFirmwareAnalysisName)
	}
	if meta.UsagePrompt == "" {
		t.Fatalf("expected loop %q to have a usage prompt", LoopFirmwareAnalysisName)
	}
}

func TestFirmwareAnalysisLoop_UsesNoOpMemoryTriage(t *testing.T) {
	invoker := newFirmwareFinalizeTestInvoker(t)
	loop, err := reactloops.CreateLoopByName(LoopFirmwareAnalysisName, invoker)
	if err != nil {
		t.Fatalf("create loop by name: %v", err)
	}
	mem := loop.GetMemoryTriage()
	if mem == nil {
		t.Fatal("expected firmware loop to install a memory triage implementation")
	}
	if mem.GetSessionID() != "noop" {
		t.Fatalf("expected firmware loop to use no-op memory triage, got session id %q", mem.GetSessionID())
	}
	result, err := mem.SearchMemory("firmware corpus", 1024)
	if err != nil {
		t.Fatalf("expected no-op memory triage search not to fail: %v", err)
	}
	if result == nil || len(result.Memories) != 0 || strings.TrimSpace(result.TotalContent) != "" {
		t.Fatalf("expected no-op memory triage to return an empty result, got %+v", result)
	}
}

func TestPopulateFirmwareReportContext_BackfillsTargetAndSections(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "mock_firmware")
	if err := os.WriteFile(targetPath, []byte("mock-binary"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	corpus := strings.Join([]string{
		"type FirmwareHeader struct { Magic [4]byte; Version uint32; Len uint32 }",
		"if string(header.Magic[:]) != \"FWUP\" { return }",
		"if len(payload) > 5 && string(payload[:4]) == \"PING\" {",
		"_ = payload[header.Len-1]",
		"panic: runtime error: index out of range [46] with length 35",
		"cmd := exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+targetIP)",
		"os/exec.Command + CombinedOutput",
	}, "\n")

	ctx := populateFirmwareReportContext(firmwareReportContext{
		TargetPath: targetPath,
		Summary:    "Confirmed command injection in main.processPayload.",
		Corpus:     corpus,
	})

	if ctx.TargetName != "mock_firmware" {
		t.Fatalf("expected target name mock_firmware, got %q", ctx.TargetName)
	}
	if ctx.TargetSize == "" || ctx.TargetSize == "unknown" {
		t.Fatalf("expected target size to be backfilled, got %q", ctx.TargetSize)
	}
	if !strings.Contains(ctx.BusinessFunctions, "PING") {
		t.Fatalf("expected business functions to mention PING branch, got:\n%s", ctx.BusinessFunctions)
	}
	if !strings.Contains(ctx.DataStructures, "FirmwareHeader") {
		t.Fatalf("expected data structures to mention FirmwareHeader, got:\n%s", ctx.DataStructures)
	}
	if !strings.Contains(ctx.DangerousFunctions, "解析器边界检查不足") {
		t.Fatalf("expected dangerous functions to include localized parser bounds finding, got:\n%s", ctx.DangerousFunctions)
	}
	if !strings.Contains(ctx.FuzzPlans, "FWUP") || !strings.Contains(ctx.FuzzPlans, "META") {
		t.Fatalf("expected fuzz plan to focus on the confirmed FWUP/META parser path, got:\n%s", ctx.FuzzPlans)
	}
}

func TestBuildReportMarkdown_AvoidsUnknownAndEmptyPlaceholdersWhenEvidenceExists(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "mock_firmware")
	if err := os.WriteFile(targetPath, []byte("mock-binary"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	ctx := populateFirmwareReportContext(firmwareReportContext{
		TargetPath: targetPath,
		Summary:    "Confirmed command injection in main.processPayload.",
		Corpus: strings.Join([]string{
			"type FirmwareHeader struct { Magic [4]byte; Version uint32; Len uint32 }",
			"if string(header.Magic[:]) != \"FWUP\" { return }",
			"if string(payload[:4]) == \"PING\" { targetIP := string(payload[4:]) }",
			"_ = payload[header.Len-1]",
			"index out of range",
			"exec.Command",
		}, "\n"),
	})

	report := buildReportMarkdown(ctx, "remaining gaps")
	for _, placeholder := range []string{"目标名称：unknown", "目标路径：unknown", "文件大小：unknown", "总大小：unknown"} {
		if strings.Contains(report, placeholder) {
			t.Fatalf("expected report to avoid unknown target placeholder %q, got:\n%s", placeholder, report)
		}
	}
	if strings.Contains(report, "暂无记录。") {
		t.Fatalf("expected report to avoid empty placeholders when evidence exists, got:\n%s", report)
	}
}

func TestFinalFirmwareReportAction_EmitsFinishedResultAndTerminates(t *testing.T) {
	invoker := newFirmwareFinalizeTestInvoker(t)
	loop := newFirmwareFinalizeTestLoop(t, invoker, finalFirmwareReportAction(invoker))

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "mock_firmware")
	if err := os.WriteFile(targetPath, []byte("mock-binary"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	loop.Set("firmware_target_path", targetPath)
	loop.Set("firmware_filename", "mock_firmware")
	loop.Set("firmware_size", "11 bytes")
	loop.Set("business_functions", "- Module: firmware package parsing")
	loop.Set("data_structures", "- FirmwareHeader { Magic[4], Version, Len }")
	loop.Set("dangerous_functions", "- main.processPayload: command injection sink")
	loop.Set("fuzz_plans", "- Seed: FWUP + version + len + PING + 127.0.0.1")

	actionHandler, err := loop.GetActionHandler("final_firmware_report")
	if err != nil {
		t.Fatalf("get action handler: %v", err)
	}

	action, err := aicommon.ExtractAction(`{"@action":"final_firmware_report","executive_summary":"Confirmed command injection and out-of-bounds risks.","remaining_gaps":"Need full decompiler evidence for more sinks."}`, "final_firmware_report")
	if err != nil {
		t.Fatalf("extract action: %v", err)
	}

	task := aicommon.NewStatefulTaskBase("firmware-final-report-task", "question", context.Background(), loop.GetEmitter())
	op := reactloops.NewActionHandlerOperator(task)
	actionHandler.ActionHandler(loop, action, op)

	terminated, opErr := op.IsTerminated()
	if opErr != nil {
		t.Fatalf("unexpected operator error: %v", opErr)
	}
	if !terminated {
		t.Fatal("expected final_firmware_report handler to terminate the loop")
	}
	if len(invoker.resultPayloads) != 1 {
		t.Fatalf("expected exactly one EmitResultAfterStream call, got %d", len(invoker.resultPayloads))
	}
	if !strings.Contains(invoker.resultPayloads[0], "# 固件分析报告") {
		t.Fatalf("expected final result payload to contain firmware report heading, got:\n%s", invoker.resultPayloads[0])
	}
	if !hasFirmwareTimelineEntry(invoker.timelineRecords, "[FIRMWARE_ANALYSIS_FINISHED]") {
		t.Fatalf("expected completion timeline entry, got %+v", invoker.timelineRecords)
	}
	if !strings.Contains(loop.Get("firmware_analysis_report"), "firmware_analysis_report.md") {
		t.Fatalf("expected report artifact path to be stored, got %q", loop.Get("firmware_analysis_report"))
	}
}

func TestInferFirmwareFindings_GoMockLinuxExpectedPositivesAndSuppressesFalsePositives(t *testing.T) {
	raw, err := os.ReadFile("/Users/john/go/src/firmware_analysis_gomock/main.go")
	if err != nil {
		t.Fatalf("read gomock source: %v", err)
	}

	findings := inferFirmwareFindings("", string(raw))
	if len(findings) == 0 {
		t.Fatal("expected inferred findings for gomock sample")
	}

	expectFinding(t, findings, firmwareFinding{
		Category:   "custom-format",
		Severity:   "info",
		Confidence: "high",
	})
	expectFinding(t, findings, firmwareFinding{
		Category:   "path-traversal",
		Severity:   "high",
		Confidence: "high",
	})
	expectFinding(t, findings, firmwareFinding{
		Category:   "untrusted-length-slicing",
		Severity:   "high",
		Confidence: "high",
	})
	expectFinding(t, findings, firmwareFinding{
		Category:   "insufficient-length-check",
		Severity:   "high",
		Confidence: "high",
	})
	expectFinding(t, findings, firmwareFinding{
		Category:   "declared-payload-length-not-validated",
		Severity:   "medium",
		Confidence: "high",
	})
	expectFinding(t, findings, firmwareFinding{
		Category:   "missing-integrity-verification",
		Severity:   "medium",
		Confidence: "medium",
	})

	for _, finding := range findings {
		switch finding.Category {
		case "path-traversal":
			expectContains(t, finding.Evidence, "filepath.Join")
			expectContains(t, finding.Evidence, "os.WriteFile")
			expectContains(t, finding.Evidence, "filename")
		case "untrusted-length-slicing":
			expectContains(t, finding.Evidence, "payload[4:6]")
			expectContains(t, finding.Evidence, "payload[6:6+filenameLen]")
		case "insufficient-length-check":
			expectContains(t, finding.Evidence, "len(payload) >= 4")
			expectContains(t, finding.Evidence, "payload[7]")
		case "declared-payload-length-not-validated":
			expectContains(t, finding.Evidence, "header.Len")
			expectContains(t, finding.Evidence, "data[12:]")
		case "missing-integrity-verification":
			expectContains(t, finding.Evidence, "FWUP magic is checked")
			expectContains(t, strings.ToLower(finding.Evidence), "no signature")
			if strings.Contains(strings.ToLower(finding.Evidence), "crc") {
				t.Fatalf("expected integrity finding to avoid CRC-specific claims, got %+v", finding)
			}
		case "custom-format":
			expectContains(t, finding.Evidence, "12-byte header")
			expectContains(t, finding.Evidence, `"FWUP"`)
		}
		if finding.Category == "command-injection" || strings.Contains(strings.ToLower(finding.Title), "command injection") {
			t.Fatalf("expected gomock sample to suppress command-injection false positive, got %+v", finding)
		}
		if strings.Contains(strings.ToLower(finding.Title), "crc") || strings.Contains(strings.ToLower(finding.MissingGuard), "crc") {
			t.Fatalf("expected gomock sample to avoid CRC-specific false positive, got %+v", finding)
		}
		if strings.Contains(strings.ToLower(finding.Title), "magic verification") || strings.Contains(strings.ToLower(finding.MissingGuard), "magic verification") {
			t.Fatalf("expected gomock sample to avoid magic-verification false positive, got %+v", finding)
		}
		if strings.Contains(strings.ToLower(finding.Evidence), "no file write sink") || strings.Contains(strings.ToLower(finding.Evidence), "no high-risk sink") {
			t.Fatalf("expected gomock sample to recognize the real file-write sink, got %+v", finding)
		}
	}
}

func TestInferDataStructures_UsesNeutralFieldNamesWithoutValidatedSemantics(t *testing.T) {
	structures := inferFirmwareDataStructures("", strings.Join([]string{
		"12-byte header parsed before payload processing",
		"magic compared before dispatch",
		"u32 read at offset 4",
		"u32 read at offset 8",
	}, "\n"))
	if len(structures) == 0 {
		t.Fatal("expected inferred data structure")
	}

	var fieldParts []string
	for _, ds := range structures {
		fieldParts = append(fieldParts, ds.Fields)
	}
	fieldsJoined := strings.ToLower(strings.Join(fieldParts, "\n"))
	if strings.Contains(fieldsJoined, "crc") || strings.Contains(fieldsJoined, "checksum") || strings.Contains(fieldsJoined, "reserved") {
		t.Fatalf("expected neutral field naming without validated semantics, got:\n%s", fieldsJoined)
	}
	if !strings.Contains(fieldsJoined, "u32_at_4") || !strings.Contains(fieldsJoined, "u32_at_8") {
		t.Fatalf("expected neutral field names like u32_at_4/u32_at_8, got:\n%s", fieldsJoined)
	}
}

func TestInferBusinessFunctions_StringMarkersAloneStayUnconfirmed(t *testing.T) {
	got := inferBusinessFunctions("", "FWUP\nSAVE\nMETA\nPING")
	if strings.TrimSpace(got) != "" {
		t.Fatalf("expected marker strings alone not to create confirmed business modules, got:\n%s", got)
	}
}

func TestInferFirmwareFindings_GenericFirmwarePayloadTextDoesNotClaimIntegrityGap(t *testing.T) {
	findings := inferFirmwareFindings("", "firmware payload parser accepts bytes and dispatches data")
	for _, finding := range findings {
		if finding.Category == "missing-integrity-verification" {
			t.Fatalf("expected generic firmware/payload wording not to claim missing cryptographic verification, got %+v", finding)
		}
	}
}

func TestNormalizeFinding_StringOnlyEvidenceIsDowngradedAndSinkRemainsUnconfirmed(t *testing.T) {
	finding := normalizeFinding(firmwareFinding{
		Title:        "Possible command execution",
		Category:     "command-injection",
		Severity:     "high",
		Confidence:   "high",
		Source:       "payload marker string",
		Transform:    "",
		Sink:         "exec string nearby",
		MissingGuard: "",
		Evidence:     "Only strings observed: PING sh exec cmd",
	})

	if finding.Category != "suspicious-command-capability" {
		t.Fatalf("expected string-only evidence to downgrade to suspicious capability, got %+v", finding)
	}
	if finding.Severity != "info" {
		t.Fatalf("expected string-only evidence severity to downgrade to info, got %+v", finding)
	}
	if finding.Confidence != "low" {
		t.Fatalf("expected string-only evidence confidence to downgrade to low, got %+v", finding)
	}
	if finding.Sink != "not confirmed" {
		t.Fatalf("expected unconfirmed sink to stay as not confirmed, got %+v", finding)
	}
	if finding.SuppressionReason == "" {
		t.Fatalf("expected suppression reason for downgraded finding, got %+v", finding)
	}
}

func TestContainsConfirmedCommandSink_FiltersStandardLibrarySymbolsWithoutCalls(t *testing.T) {
	if containsConfirmedCommandSink("imports os/exec and mentions exec package symbol") {
		t.Fatal("expected plain stdlib symbol mention without call syntax to be filtered out")
	}
	if !containsConfirmedCommandSink(`cmd := exec.Command("sh", "-c", userInput)`) {
		t.Fatal("expected concrete exec.Command call to count as confirmed sink")
	}
}

func TestNormalizeFinding_RequiresEvidenceChainOrExplicitMissingGuard(t *testing.T) {
	finding := normalizeFinding(firmwareFinding{
		Title:      "Path write risk",
		Category:   "path-traversal",
		Severity:   "high",
		Confidence: "high",
		Source:     "payload filename",
		Transform:  "",
		Sink:       "",
		Evidence:   "path join seen near write logic",
	})

	if finding.Severity != "info" {
		t.Fatalf("expected incomplete evidence chain to downgrade severity, got %+v", finding)
	}
	if finding.Sink != "not confirmed" {
		t.Fatalf("expected missing sink to render as not confirmed, got %+v", finding)
	}

	withGuardGap := normalizeFinding(firmwareFinding{
		Title:        "Parser bounds hardening issue",
		Category:     "insufficient-length-check",
		Severity:     "high",
		Confidence:   "medium",
		Source:       "payload bytes",
		Transform:    "branch guard then indexed read",
		Sink:         "indexed memory access into payload buffer",
		MissingGuard: "highest accessed index is not proven in bounds",
		Evidence:     "len(payload) >= 4 followed by payload[7]",
	})
	if withGuardGap.Severity != "high" {
		t.Fatalf("expected explicit source-transform-sink plus guard gap to preserve severity, got %+v", withGuardGap)
	}
}

func TestDetectInsufficientLengthCheckPattern_RecognizesMoreParserBoundsShapes(t *testing.T) {
	corpus := strings.Join([]string{
		"if len(payload) < 8 { return }",
		"_ = payload[header.Len-1]",
		"payload[10]",
	}, "\n")
	if !detectInsufficientLengthCheckPattern(corpus) {
		t.Fatalf("expected parser-bounds detector to recognize indexed access beyond guarded range")
	}
}

func TestDetectInsufficientLengthCheckPattern_DoesNotFireWhenBoundsAreProven(t *testing.T) {
	corpus := strings.Join([]string{
		"if len(payload) >= 8 {",
		"_ = payload[7]",
		"}",
	}, "\n")
	if detectInsufficientLengthCheckPattern(corpus) {
		t.Fatalf("expected parser-bounds detector to stay quiet when highest index is proven in bounds")
	}
}

func TestNormalizeFinding_PreservesConcreteWriteFileSink(t *testing.T) {
	finding := normalizeFinding(firmwareFinding{
		Title:        "Path traversal leading to arbitrary file write",
		Category:     "path-traversal",
		Severity:     "high",
		Confidence:   "high",
		Source:       "SAVE payload filename",
		Transform:    `filepath.Join("/tmp/fwupload", filename)`,
		Sink:         "os.WriteFile",
		MissingGuard: "no canonical containment check after join",
		Evidence:     `SAVE payload filename -> filepath.Join("/tmp/fwupload", filename) -> os.WriteFile`,
	})
	if finding.Severity != "high" || finding.Sink != "os.WriteFile" {
		t.Fatalf("expected concrete write sink to remain a high-severity finding, got %+v", finding)
	}
}

func TestInferFuzzPlans_GoMockFocusesOnRealAttackSurfaceNotCRC(t *testing.T) {
	raw, err := os.ReadFile("/Users/john/go/src/firmware_analysis_gomock/main.go")
	if err != nil {
		t.Fatalf("read gomock source: %v", err)
	}
	findings := inferFirmwareFindings("", string(raw))
	structures := inferFirmwareDataStructures("", string(raw))
	plans := inferFuzzPlans("", string(raw), findings, structures)
	if len(plans) == 0 {
		t.Fatal("expected at least one fuzz plan")
	}
	plan := renderFuzzPlanMarkdown(plans[0])
	expectContains(t, plan, "META")
	expectContains(t, plan, "filenameLen")
	expectContains(t, plan, "header.Len")
	expectContains(t, plan, "paths")
	if strings.Contains(strings.ToLower(plan), "crc") {
		t.Fatalf("expected fuzz plan to avoid nonexistent CRC focus, got:\n%s", plan)
	}
}

func TestPopulateFirmwareReportContext_DirectoryTargetBuildsInventoryAndAvoidsUnknown(t *testing.T) {
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "startup.cfg"), []byte("local-user admin password irreversible-cipher abcdef123456\n"))
	mustWriteFile(t, filepath.Join(tmpDir, "60.83.206.131-running.cfg"), []byte("snmp-agent usm-user v3 auth md5 deadbeef privacy aes128 cafebabe\n"))
	mustWriteFile(t, filepath.Join(tmpDir, "hostkey"), []byte{0x01, 0x02, 0x03, 0x04})
	mustWriteZipFile(t, filepath.Join(tmpDir, "vrpcfg.zip"), map[string]string{
		"vrpcfg.cfg": "local-user admin password irreversible-cipher zzzzzzzzzzz\n",
	})

	ctx := populateFirmwareReportContext(firmwareReportContext{
		TargetPath: tmpDir,
		Summary:    "directory corpus test",
	})

	if ctx.TargetType != "directory / firmware corpus" {
		t.Fatalf("expected directory target type, got %+v", ctx)
	}
	if ctx.TargetPath != tmpDir {
		t.Fatalf("expected target path %q, got %+v", tmpDir, ctx)
	}
	if ctx.TargetName != filepath.Base(tmpDir) {
		t.Fatalf("expected target name %q, got %+v", filepath.Base(tmpDir), ctx)
	}
	if ctx.TargetFileCount < 4 {
		t.Fatalf("expected file count >= 4, got %+v", ctx)
	}
	if !strings.Contains(ctx.InventoryMarkdown, "样本清单") || !strings.Contains(ctx.InventoryMarkdown, "startup.cfg") || !strings.Contains(ctx.InventoryMarkdown, "vrpcfg.zip") {
		t.Fatalf("expected inventory markdown to mention created samples, got:\n%s", ctx.InventoryMarkdown)
	}

	report := buildReportMarkdown(ctx, "")
	if strings.Contains(report, "文件大小：") || strings.Contains(report, "目标路径：unknown") || strings.Contains(report, "总大小：unknown") {
		t.Fatalf("expected directory report to use directory-level metadata only, got:\n%s", report)
	}
	if !strings.Contains(report, "目标类型：固件语料目录") {
		t.Fatalf("expected directory report to include localized target type, got:\n%s", report)
	}
}

func TestBuildReportMarkdown_MasksSensitiveConfigValuesForDirectoryCorpus(t *testing.T) {
	ctx := firmwareReportContext{
		TargetType:      "directory / firmware corpus",
		TargetPath:      "/tmp/corpus",
		TargetName:      "corpus",
		TargetTotalSize: "1024 bytes",
		TargetFileCount: 2,
		TargetScope:     "top-level + selected archive members",
		InventoryMarkdown: strings.Join([]string{
			"## 样本清单",
			"| 文件 | 大小 | 初步类型 | 设备/平台 | 识别依据 |",
			"|---|---:|---|---|---|",
			"| startup.cfg | 128 bytes | config | unknown | local-user password irreversible-cipher: <masked> |",
		}, "\n"),
		FindingEntries: []firmwareFinding{{
			Title:      "Exported configs expose network-device authentication material",
			Category:   "sensitive-data-exposure",
			Severity:   "high",
			Confidence: "high",
			Scope:      "corpus-level",
			AffectedFiles: []string{
				"/tmp/corpus/startup.cfg",
				"/tmp/corpus/vrpcfg.zip!/vrpcfg.cfg",
			},
			Evidence:     "startup.cfg:L1 contains local-user password irreversible-cipher: <masked>\nvrpcfg.cfg:L1 contains local-user admin password irreversible-cipher: <masked>\nvrpcfg.cfg:L2 contains SNMPv3 authentication-mode md5: <masked>",
			Limitations:  "values masked by default",
			Source:       "exported config corpus",
			Transform:    "config lines parsed for local-user and snmp credential directives",
			Sink:         "not confirmed",
			MissingGuard: "sensitive material present in exported configs",
		}},
	}
	ctx.DangerousFunctions = renderFindingsMarkdown(ctx.FindingEntries, "")

	report := buildReportMarkdown(ctx, "")
	if strings.Contains(report, "abcdef123456") || strings.Contains(report, "deadbeef") || strings.Contains(report, "cafebabe") {
		t.Fatalf("expected report to mask sensitive values, got:\n%s", report)
	}
	if !strings.Contains(report, "<masked>") {
		t.Fatalf("expected masked placeholders in report, got:\n%s", report)
	}
	if !strings.Contains(report, "关联文件") {
		t.Fatalf("expected localized affected files label, got:\n%s", report)
	}
	if !strings.Contains(report, "风险发现") || !strings.Contains(report, "高危（High）") || !strings.Contains(report, "可信度：高") {
		t.Fatalf("expected Chinese finding presentation, got:\n%s", report)
	}
}

func TestBuildReportMarkdown_LocalizesPresentationLabels(t *testing.T) {
	ctx := firmwareReportContext{
		TargetType:        "file",
		TargetPath:        "/tmp/firmware.bin",
		TargetName:        "firmware.bin",
		TargetSize:        "123 bytes",
		TargetScope:       "single target",
		BusinessFunctions: "### FWUP 固件解析器\n\n- 功能说明：解析器示例\n- 识别依据：示例证据\n- 可信度：高",
		DataStructureEntries: []firmwareDataStructure{{
			Name:             "FirmwareHeader",
			Location:         "parseFirmware",
			Fields:           "Magic[4], Version, Len",
			ProducerConsumer: "parseFirmware / processPayload",
			Evidence:         "binary.Read + magic compare",
			Confidence:       "high",
			SemanticsStatus:  "validated",
		}},
		FindingEntries: []firmwareFinding{{
			Title:        "SAVE 命令路径穿越导致任意文件写入",
			Category:     "path-traversal",
			Severity:     "high",
			Confidence:   "high",
			Source:       "payload filename",
			Transform:    "payload -> filepath.Join -> os.WriteFile",
			Sink:         "os.WriteFile",
			MissingGuard: "缺少目录包含校验",
			Evidence:     "filepath.Join + os.WriteFile",
		}},
		FuzzPlanEntries: []firmwareFuzzPlan{{
			Target:           "main.processPayload SAVE 分支",
			Entrypoint:       "main.parseFirmware -> main.processPayload",
			InputModel:       "FWUP 头 + SAVE payload",
			MutationStrategy: "变异文件名与长度",
			Oracle:           "panic / 越界写入",
			SetupNotes:       "隔离目录运行",
			Priority:         "high",
		}},
	}
	ctx = populateFirmwareReportContext(ctx)
	report := buildReportMarkdown(ctx, "静态分析为主")
	for _, needle := range []string{
		"目标类型：单文件",
		"分析范围：单个目标文件",
		"结构名称：FirmwareHeader",
		"问题类型：路径穿越（Path Traversal）",
		"危险操作：os.WriteFile",
		"修复建议：",
		"测试目标：main.processPayload SAVE 分支",
		"判定条件：panic / 越界写入",
		"环境要求：隔离目录运行",
		"优先级：高危（High）",
	} {
		if !strings.Contains(report, needle) {
			t.Fatalf("expected localized report to contain %q, got:\n%s", needle, report)
		}
	}
}

func TestRenderInventoryMarkdown_UsesChineseEvidenceAndSpecificTypes(t *testing.T) {
	tmpDir := t.TempDir()
	startupPath := filepath.Join(tmpDir, "startup.cfg")
	zipPath := filepath.Join(tmpDir, "vrpcfg.zip")
	mustWriteFile(t, startupPath, []byte("local-user admin password irreversible-cipher abcdef123456\nsysname CoreSwitch\n"))
	mustWriteZipFile(t, zipPath, map[string]string{
		"vrpcfg.cfg": "snmp-agent usm-user v3 auth md5 deadbeef privacy aes128 cafebabe\n",
	})

	startupInfo, err := os.Stat(startupPath)
	if err != nil {
		t.Fatalf("stat startup cfg: %v", err)
	}
	zipInfo, err := os.Stat(zipPath)
	if err != nil {
		t.Fatalf("stat zip: %v", err)
	}

	markdown := renderInventoryMarkdown([]firmwareInventoryEntry{
		buildInventoryEntry(startupPath, startupInfo, filepath.Base(startupPath)),
		buildInventoryEntry(zipPath, zipInfo, filepath.Base(zipPath)),
	})

	for _, needle := range []string{
		"| 文件 | 大小 | 初步类型 | 平台/厂商 | 识别依据 |",
		"设备启动配置",
		"配置压缩包",
		"配置中包含 local-user/password/snmp/interface 等关键字段",
		"ZIP 包包含文本配置成员 vrpcfg.cfg",
	} {
		if !strings.Contains(markdown, needle) {
			t.Fatalf("expected inventory markdown to contain %q, got:\n%s", needle, markdown)
		}
	}
}

func TestInferCorpusFindings_PreservesSensitiveAndAttackSurfaceClassification(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "startup.cfg",
			DetectedType: "device-startup-config",
			Evidence:     []string{"配置中包含 local-user/password/snmp/interface 等关键字段", "startup.cfg:L1 包含本地用户口令材料：password <masked>"},
		},
		{
			Name:         "hostkey",
			DetectedType: "device-key-material",
			Evidence:     []string{"文件名包含 key，且内容呈现二进制高熵 blob 特征"},
		},
		{
			Name:         "system.bin",
			DetectedType: "vendor-firmware-image",
			Evidence:     []string{"字符串中出现 SSH/Telnet/Console 等管理面线索", "二进制中出现 SquashFS/gzip/ELF/uImage 标记"},
		},
	}, "/tmp/corpus")

	expectFinding(t, findings, firmwareFinding{Category: "sensitive-data-exposure", Severity: "high", Confidence: "high"})
	expectFinding(t, findings, firmwareFinding{Category: "sensitive-data-presence", Severity: "medium", Confidence: "medium"})
	expectFinding(t, findings, firmwareFinding{Category: "attack-surface", Severity: "info", Confidence: "medium"})

	for _, finding := range findings {
		if finding.Category == "attack-surface" && finding.Confidence == "low" {
			t.Fatalf("expected attack-surface finding to remain medium confidence instead of being downgraded, got %+v", finding)
		}
		if finding.Category == "attack-surface" && strings.Contains(strings.ToLower(finding.Title), "command") {
			t.Fatalf("expected attack-surface finding to stay as attack-surface rather than command risk, got %+v", finding)
		}
	}
}

func TestBuildFirmwareTargetModel_ArchiveUsesArchiveMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "config-backup.zip")
	mustWriteZipFile(t, archivePath, map[string]string{
		"backup.cfg": "local-user admin password irreversible-cipher abcdef123456\n",
	})

	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}

	model := buildFirmwareTargetModel(archivePath, info)
	if model.Type != "archive" {
		t.Fatalf("expected archive target type, got %+v", model)
	}
	if model.AnalysisScope != "archive members inspected" {
		t.Fatalf("expected archive analysis scope, got %+v", model)
	}
	if len(model.Inventory) != 1 || !model.Inventory[0].IsArchive || model.Inventory[0].MemberCount != 1 {
		t.Fatalf("expected archive inventory with one inspected member, got %+v", model.Inventory)
	}
	if got := localizeDetectedType(model.Inventory[0].DetectedType); got != "配置压缩包" {
		t.Fatalf("expected config archive detected type, got %q", got)
	}
}

func TestBuildFirmwareTargetModel_ExtractedFilesystemUsesRecursiveMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	mustWriteFile(t, filepath.Join(tmpDir, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"))
	mustWriteFile(t, filepath.Join(tmpDir, "etc", "shadow"), []byte("root:*:19793:0:99999:7:::\n"))
	mustWriteFile(t, filepath.Join(tmpDir, "bin", "busybox"), []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	mustWriteFile(t, filepath.Join(tmpDir, "www", "index.html"), []byte("<html>ok</html>"))

	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("stat rootfs: %v", err)
	}

	model := buildFirmwareTargetModel(tmpDir, info)
	if model.Type != "extracted filesystem" {
		t.Fatalf("expected extracted filesystem target, got %+v", model)
	}
	if model.AnalysisScope != "recursive filesystem inspection" {
		t.Fatalf("expected recursive scope, got %+v", model)
	}
	if model.DetectedType != "Linux / BusyBox" {
		t.Fatalf("expected Linux / BusyBox platform, got %+v", model)
	}
	if model.FileCount < 4 {
		t.Fatalf("expected recursive file count >= 4, got %+v", model)
	}
	for _, needle := range []string{"/etc", "/bin", "/www"} {
		if !containsSlice(model.KeyPaths, needle) {
			t.Fatalf("expected key paths to contain %q, got %+v", needle, model.KeyPaths)
		}
	}
	if len(model.Inventory) == 0 {
		t.Fatalf("expected selected rootfs inventory entries, got %+v", model)
	}
}

func TestBuildReportMarkdown_GroupsFindingsAndShowsRootfsDetails(t *testing.T) {
	ctx := populateFirmwareReportContext(firmwareReportContext{
		TargetType:         "extracted filesystem",
		TargetPath:         "/tmp/rootfs",
		TargetName:         "rootfs",
		TargetTotalSize:    "about 12MB",
		TargetFileCount:    42,
		TargetScope:        "recursive filesystem inspection",
		TargetDetectedType: "Linux / BusyBox",
		TargetKeyPaths:     []string{"/etc", "/bin", "/www"},
		FindingEntries: []firmwareFinding{
			{
				Title:         "路径穿越导致任意文件写入",
				Category:      "path-traversal",
				Severity:      "high",
				Confidence:    "high",
				Source:        "固件 payload 文件名字段",
				Transform:     "payload filename -> filepath.Join -> os.WriteFile",
				Sink:          "os.WriteFile",
				MissingGuard:  "缺少目录包含校验",
				Evidence:      "filepath.Join + os.WriteFile",
				AffectedFiles: []string{"/tmp/rootfs/bin/upgrader"},
			},
			{
				Title:         "导出的设备配置暴露认证材料",
				Category:      "sensitive-data-exposure",
				Severity:      "high",
				Confidence:    "high",
				Source:        "配置备份文件",
				Transform:     "解析出 local-user 和 SNMPv3 认证字段",
				Sink:          "not confirmed",
				MissingGuard:  "配置导出未脱敏",
				Evidence:      "startup.cfg:L1 包含本地用户口令材料：password <masked>",
				AffectedFiles: []string{"/tmp/rootfs/etc/config.cfg"},
			},
			{
				Title:        "发现 CLI 管理面与命令解析攻击面线索",
				Category:     "attack-surface",
				Severity:     "info",
				Confidence:   "medium",
				Source:       "固件镜像字符串与配置线索",
				Transform:    "样本清单与配置证据指向 SSH/Telnet/Console",
				Sink:         "not confirmed",
				MissingGuard: "未确认输入到命令执行函数的数据流",
				Evidence:     "观察到 SSH/Telnet/Console 线索",
			},
			{
				Title:             "Suspicious command-execution capability",
				Category:          "suspicious-command-capability",
				Severity:          "info",
				Confidence:        "low",
				Source:            "字符串命中",
				Transform:         "仅观察到 shell/system 字符串",
				Sink:              "not confirmed",
				MissingGuard:      "not recorded",
				Evidence:          "nearby shell/system strings",
				SuppressionReason: "尚未确认真实命令执行 sink",
			},
		},
	})

	report := buildReportMarkdown(ctx, "")
	for _, needle := range []string{
		"- 已识别平台：Linux / BusyBox",
		"- 关键目录：/etc、/bin、/www",
		"### 已确认风险",
		"### 敏感信息与敏感材料",
		"### 攻击面线索与组件观察",
		"### 待验证假设",
	} {
		if !strings.Contains(report, needle) {
			t.Fatalf("expected grouped report to contain %q, got:\n%s", needle, report)
		}
	}
}

func TestDeliverFirmwareReport_EmitsOnceAndStoresArtifact(t *testing.T) {
	invoker := newFirmwareFinalizeTestInvoker(t)
	loop, err := reactloops.NewReActLoop(LoopFirmwareAnalysisName, invoker,
		reactloops.WithPersistentInstruction("test"),
		reactloops.WithMaxIterations(2),
	)
	if err != nil {
		t.Fatalf("new loop: %v", err)
	}
	loop.Set("firmware_target_type", "directory / firmware corpus")
	loop.Set("firmware_filename", "固件")
	loop.Set("firmware_target_total_size", "about 280MB")
	loop.Set("firmware_target_file_count", "13")
	loop.Set(firmwareFindingsStateKey, `{"title":"导出的设备配置暴露认证材料","category":"sensitive-data-exposure","severity":"high","confidence":"high","evidence":"startup.cfg:L1 包含本地用户口令材料：password <masked>","source":"配置文件","transform":"解析配置认证字段","sink":"not confirmed","missing_guard":"配置导出未脱敏"}`)

	report, artifact := deliverFirmwareReport(loop, invoker, "", "")
	if strings.TrimSpace(report) == "" {
		t.Fatal("expected non-empty report")
	}
	if strings.TrimSpace(artifact) == "" || !strings.Contains(artifact, "firmware_analysis_report.md") {
		t.Fatalf("expected artifact path, got %q", artifact)
	}
	if len(invoker.resultPayloads) != 1 {
		t.Fatalf("expected exactly one emitted result, got %d", len(invoker.resultPayloads))
	}

	report2, artifact2 := deliverFirmwareReport(loop, invoker, "", "")
	if report2 == "" || artifact2 == "" {
		t.Fatalf("expected second call to preserve report and artifact, got report=%q artifact=%q", report2, artifact2)
	}
	if len(invoker.resultPayloads) != 1 {
		t.Fatalf("expected second delivery attempt not to emit duplicate result, got %d", len(invoker.resultPayloads))
	}
}

func TestDeliverFirmwareReport_SparseContextStillEmitsReadableReport(t *testing.T) {
	invoker := newFirmwareFinalizeTestInvoker(t)
	targetDir := t.TempDir()
	loop, err := reactloops.NewReActLoop(LoopFirmwareAnalysisName, invoker,
		reactloops.WithPersistentInstruction("test"),
		reactloops.WithMaxIterations(1),
	)
	if err != nil {
		t.Fatalf("new loop: %v", err)
	}
	loop.Set("firmware_target_type", "directory / firmware corpus")
	loop.Set("firmware_filename", filepath.Base(targetDir))
	loop.Set("firmware_target_path", targetDir)

	report, artifact := deliverFirmwareReport(loop, invoker, "", "")
	if strings.TrimSpace(report) == "" {
		t.Fatal("expected report to be generated")
	}
	expectContains(t, report, "# 固件分析报告")
	expectContains(t, report, "目标范围")
	expectContains(t, report, "风险发现")
	if strings.TrimSpace(artifact) == "" {
		t.Fatalf("expected fallback artifact path, got %q", artifact)
	}
	if len(invoker.resultPayloads) != 1 {
		t.Fatalf("expected fallback report to emit one result, got %d", len(invoker.resultPayloads))
	}
}

func TestSynthesizeReportSummary_CorpusSeparatesVendorsAndStaysConservative(t *testing.T) {
	ctx := firmwareReportContext{
		TargetType:      "directory / firmware corpus",
		TargetPath:      "/Users/john/Desktop/固件",
		TargetName:      "固件",
		TargetTotalSize: "about 280MB",
		TargetFileCount: 13,
		InventoryEntries: []firmwareInventoryEntry{
			{Name: "S5720SI-V200R019C10SPC500.cc", DisplayPath: "S5720SI-V200R019C10SPC500.cc", DetectedType: "vendor-firmware-image", Platform: "Huawei S5720SI / VRP"},
			{Name: "s5570s_ei-cmw710-system-r1107.bin", DisplayPath: "s5570s_ei-cmw710-system-r1107.bin", DetectedType: "vendor-firmware-image", Platform: "H3C S5570S / Comware"},
			{Name: "startup.cfg", DisplayPath: "startup.cfg", DetectedType: "device-startup-config", Platform: "H3C S5570S / Comware"},
			{Name: "vrpcfg.zip", DisplayPath: "vrpcfg.zip", DetectedType: "config-archive", Platform: "Huawei S5720SI / VRP"},
		},
		FindingEntries: []firmwareFinding{
			{Title: "导出的设备配置暴露认证材料", Category: "sensitive-data-exposure", Severity: "high", Confidence: "high"},
			{Title: "目录中存在疑似设备密钥材料", Category: "sensitive-data-presence", Severity: "medium", Confidence: "medium"},
			{Title: "设备私有数据暴露接口和拓扑信息", Category: "private-data-exposure", Severity: "medium", Confidence: "medium"},
			{Title: "发现固件镜像攻击面线索", Category: "attack-surface", Severity: "info", Confidence: "medium"},
		},
	}

	got := synthesizeReportSummary(ctx)
	expectContains(t, got, "Huawei S5720SI / VRP")
	expectContains(t, got, "H3C S5570S / Comware")
	expectContains(t, got, "导出的配置文件包含认证材料")
	expectContains(t, got, "疑似设备密钥材料")
	if strings.Contains(got, "H3C S5570/S5720") || strings.Contains(got, "4项高危") || strings.Contains(got, "SSH私钥明文暴露") {
		t.Fatalf("expected conservative multi-vendor summary, got:\n%s", got)
	}
}

func TestSummarizeArchiveEvidence_TreatsPrintableCfgAsTextConfig(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "vrpcfg.zip")
	mustWriteZipFile(t, zipPath, map[string]string{
		"vrpcfg.cfg": strings.Join([]string{
			"!Software Version V200R011C10SPC600",
			"sysname Tuanjielu-S5720-E",
			"local-user admin password irreversible-cipher abcdef123456",
		}, "\n"),
	})

	evidence := strings.Join(summarizeArchiveEvidence(zipPath), "\n")
	expectContains(t, evidence, "文本配置成员")
	if strings.Contains(strings.ToLower(evidence), "binary") || strings.Contains(strings.ToLower(evidence), "tlv") {
		t.Fatalf("expected text config evidence instead of binary/TLV inference, got:\n%s", evidence)
	}
}

func TestInferCorpusFindings_SplitsKeyAndPrivateDataAndAvoidsDuplication(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "startup.cfg",
			DetectedType: "device-startup-config",
			Evidence: []string{
				"startup.cfg:L1 包含本地用户口令材料：password <masked>",
				"startup.cfg:L2 包含 SSH/stelnet/console 管理面配置：stelnet server enable",
				"startup.cfg:L3 包含管理接口地址信息：interface Vlanif10",
			},
		},
		{
			Name:         "vrpcfg.zip",
			DetectedType: "config-archive",
			IsArchive:    true,
			Members:      []string{"vrpcfg.cfg, 8298 bytes"},
			Evidence:     []string{"ZIP 包包含文本配置成员 vrpcfg.cfg", "vrpcfg.cfg:L48 包含配置敏感字段：local-user admin password irreversible-cipher <masked>"},
		},
		{
			Name:         "hostkey",
			DetectedType: "device-key-material",
			Evidence:     []string{"文件名包含 key/private 等敏感材料线索", "内容呈现二进制高熵 blob 特征"},
		},
		{
			Name:         "private-data.txt",
			DetectedType: "device-private-data",
			Evidence:     []string{"文件包含 Console / GigabitEthernet / Vlanif / NULL0 等接口名"},
		},
	}, "/tmp/corpus")

	var cfgCount int
	var keySeen bool
	var privateSeen bool
	for _, finding := range findings {
		switch finding.Category {
		case "sensitive-data-exposure":
			cfgCount++
		case "sensitive-data-presence":
			keySeen = true
		case "private-data-exposure":
			privateSeen = true
		}
	}
	if cfgCount != 1 {
		t.Fatalf("expected one merged config exposure finding, got %+v", findings)
	}
	if !keySeen || !privateSeen {
		t.Fatalf("expected separate key and private-data findings, got %+v", findings)
	}
}

func TestSuggestRemediation_UsesCategorySpecificAdvice(t *testing.T) {
	got := suggestRemediation(firmwareFinding{Category: "sensitive-data-exposure"})
	for _, needle := range []string{"导出配置前脱敏", "轮换", "SNMPv3"} {
		if !strings.Contains(got, needle) {
			t.Fatalf("expected sensitive-data remediation to contain %q, got %q", needle, got)
		}
	}
	if generic := suggestRemediation(firmwareFinding{Category: "suspicious-command-capability"}); strings.Contains(generic, "边界检查") {
		t.Fatalf("expected command-capability remediation to be attack-surface specific, got %q", generic)
	}
}

func TestSynthesizeReportSummary_MatchesHighSeverityFindings(t *testing.T) {
	ctx := firmwareReportContext{
		TargetType:      "directory / firmware corpus",
		TargetName:      "固件",
		TargetTotalSize: "about 280MB",
		TargetFileCount: 13,
		FindingEntries: []firmwareFinding{
			{Title: "导出的设备配置暴露认证材料", Category: "sensitive-data-exposure", Severity: "high", Confidence: "high"},
			{Title: "发现固件镜像攻击面线索", Category: "attack-surface", Severity: "info", Confidence: "medium"},
		},
	}
	got := synthesizeReportSummary(ctx)
	if strings.Contains(got, "无高风险确认结论") {
		t.Fatalf("expected summary to stay consistent with high-severity findings, got:\n%s", got)
	}
	expectContains(t, got, "确认的高风险主要是导出的配置文件包含认证材料")
}

func TestDetectPlatformFromName_RecognizesComwareAndVRPPerFile(t *testing.T) {
	tmpDir := t.TempDir()
	h3cConfig := filepath.Join(tmpDir, "startup.cfg")
	if err := os.WriteFile(h3cConfig, []byte("version 7.1.070, Release 1107\nsysname S5570S-Core\n"), 0o644); err != nil {
		t.Fatalf("write H3C config: %v", err)
	}
	genericConfig := filepath.Join(tmpDir, "backup", "startup.cfg")
	if err := os.MkdirAll(filepath.Dir(genericConfig), 0o755); err != nil {
		t.Fatalf("mkdir generic config: %v", err)
	}
	if err := os.WriteFile(genericConfig, []byte("hostname generic-switch\ninterface eth0\n"), 0o644); err != nil {
		t.Fatalf("write generic config: %v", err)
	}
	cases := map[string]string{
		"/tmp/S5720SI-V200R019C10SPC500.cc":      "Huawei S5720SI / VRP",
		"/tmp/S5720SI-running.cfg":               "Huawei S5720SI / VRP",
		"/tmp/vrpcfg.zip":                        "Huawei S5720SI / VRP",
		"/tmp/s5570s_ei-cmw710-system-r1107.bin": "H3C S5570S / Comware 7.1 R1107",
		h3cConfig:                                "H3C S5570S / Comware 7.1 R1107",
		genericConfig:                            "unknown",
	}
	for path, want := range cases {
		if got := detectPlatformFromName(path); got != want {
			t.Fatalf("path %s: want %q, got %q", path, want, got)
		}
	}
}

func TestInferCorpusFindings_ConfigEvidenceDoesNotCrossFiles(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "startup.cfg",
			DetectedType: "device-startup-config",
			Evidence: []string{
				"startup.cfg:L1 包含本地用户口令材料：password <masked>",
				"startup.cfg:L2 包含 SSH/stelnet/console 管理面配置：stelnet server enable",
			},
		},
		{
			Name:         "60.83.206.131-running.cfg",
			DetectedType: "device-running-config",
			Evidence: []string{
				"60.83.206.131-running.cfg:L8 包含 SNMP 认证/加密材料：authentication-mode md5 <masked>",
			},
		},
	}, "/tmp/corpus")

	var cfgFinding firmwareFinding
	for _, finding := range findings {
		if finding.Category == "sensitive-data-exposure" {
			cfgFinding = finding
			break
		}
	}
	expectContains(t, cfgFinding.Evidence, "startup.cfg:L1")
	expectContains(t, cfgFinding.Evidence, "60.83.206.131-running.cfg:L8")
	if strings.Contains(cfgFinding.Evidence, "startup.cfg:L8") {
		t.Fatalf("expected per-file config evidence to stay attached to the correct file, got:\n%s", cfgFinding.Evidence)
	}
}

func TestInferCorpusFindings_ConfigExposureOnlyAffectsFilesWithAuthenticationMaterial(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "startup.cfg",
			DetectedType: "device-startup-config",
			Evidence:     []string{"startup.cfg:L2 包含 SSH/stelnet/console 管理面配置：stelnet server enable"},
		},
		{
			Name:         "running.cfg",
			DetectedType: "device-running-config",
			Evidence:     []string{"running.cfg:L8 包含 SNMP 认证/加密材料：authentication-mode md5 <masked>"},
		},
	}, "/tmp/corpus")

	var cfgFinding firmwareFinding
	for _, finding := range findings {
		if finding.Category == "sensitive-data-exposure" {
			cfgFinding = finding
			break
		}
	}
	if len(cfgFinding.AffectedFiles) != 1 || !strings.HasSuffix(cfgFinding.AffectedFiles[0], "running.cfg") {
		t.Fatalf("expected only the credential-bearing config to be affected, got %+v", cfgFinding.AffectedFiles)
	}
}

func TestInferCorpusFindings_KeyBlobStaysConservative(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "hostkey",
			DetectedType: "device-key-material",
			Evidence:     []string{"文件名包含 key/private 等敏感材料线索", "内容呈现二进制高熵 blob 特征"},
		},
		{
			Name:         "serverkey",
			DetectedType: "device-key-material",
			Evidence:     []string{"文件名包含 key/private 等敏感材料线索", "内容呈现二进制高熵 blob 特征"},
		},
	}, "/tmp/corpus")

	var keyFinding firmwareFinding
	for _, finding := range findings {
		if finding.Category == "sensitive-data-presence" {
			keyFinding = finding
			break
		}
	}
	if keyFinding.Severity != "medium" || keyFinding.Confidence != "medium" {
		t.Fatalf("expected conservative key-blob grading, got %+v", keyFinding)
	}
	if strings.Contains(strings.ToLower(keyFinding.Title), "ssh") || strings.Contains(strings.ToLower(keyFinding.Evidence), "der") || strings.Contains(strings.ToLower(keyFinding.Evidence), "明文") {
		t.Fatalf("expected no SSH/DER/plaintext overclaim, got %+v", keyFinding)
	}
}

func TestInferCorpusFindings_ParsedPrivateKeyIsHighConfidenceExposure(t *testing.T) {
	findings := inferCorpusFindingsFromInventory([]firmwareInventoryEntry{
		{
			Name:         "ssh_host_rsa_key",
			DetectedType: "private-key-file",
			Evidence:     []string{"文件头呈现标准 PEM 私钥标记"},
		},
	}, "/tmp/corpus")

	expectFinding(t, findings, firmwareFinding{Category: "private-key-exposure", Severity: "high", Confidence: "high"})
}

func TestDetectSingleFileType_OnlyPromotesParsableUnencryptedPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	validPath := filepath.Join(t.TempDir(), "hostkey")
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(validPath, validPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if got := detectSingleFileType(validPath); got != "private-key-file" {
		t.Fatalf("expected parsed private key type, got %q", got)
	}

	unverifiedPath := filepath.Join(t.TempDir(), "serverkey")
	if err := os.WriteFile(unverifiedPath, []byte("-----BEGIN PRIVATE KEY-----\nnot-parseable\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("write unverified key blob: %v", err)
	}
	if got := detectSingleFileType(unverifiedPath); got != "device-key-material" {
		t.Fatalf("expected marker-only key to stay conservative, got %q", got)
	}
}

func TestSummarizeConfigEvidence_PrioritizesAuthenticationMaterialOverContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "running.cfg")
	content := strings.Join([]string{
		"interface Vlanif10",
		"interface GigabitEthernet0/0/1",
		"stelnet server enable",
		"local-user admin password irreversible-cipher secret-value",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	evidence := strings.Join(summarizeConfigEvidence(path), "\n")
	expectContains(t, evidence, "本地用户口令材料")
	if strings.Contains(evidence, "secret-value") {
		t.Fatalf("expected authentication material to be masked, got:\n%s", evidence)
	}
}

func TestInferFuzzPlans_CorpusUsesCorpusValidationPlanInsteadOfFWUPTemplate(t *testing.T) {
	plans := inferFuzzPlans("", "", []firmwareFinding{
		{Category: "attack-surface", Severity: "info", Confidence: "medium"},
		{Category: "sensitive-data-exposure", Severity: "high", Confidence: "high"},
	}, nil)
	if len(plans) == 0 {
		t.Fatal("expected at least one fuzz plan")
	}
	rendered := renderFuzzPlanMarkdown(plans[0])
	forbidden := []string{"FWUP", "SAVE", "filenameLen", "write escaping", "path traversal"}
	for _, needle := range forbidden {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(needle)) {
			t.Fatalf("expected corpus fuzz plan to avoid single-parser template %q, got:\n%s", needle, rendered)
		}
	}
	expectContains(t, rendered, "固件容器解包验证")
	expectContains(t, rendered, "配置导入解析器")
}

func expectFinding(t *testing.T, findings []firmwareFinding, want firmwareFinding) {
	t.Helper()
	for _, finding := range findings {
		if finding.Category == want.Category && finding.Severity == want.Severity && finding.Confidence == want.Confidence {
			return
		}
	}
	t.Fatalf("expected finding category=%s severity=%s confidence=%s, got %+v", want.Category, want.Severity, want.Confidence, findings)
}

func expectContains(t *testing.T, got string, needle string) {
	t.Helper()
	if !strings.Contains(got, needle) {
		t.Fatalf("expected %q to contain %q", got, needle)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func containsSlice(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func mustWriteZipFile(t *testing.T, path string, members map[string]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip %s: %v", path, err)
	}
	defer file.Close()
	zw := zip.NewWriter(file)
	for name, content := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create member %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write member %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip %s: %v", path, err)
	}
}
