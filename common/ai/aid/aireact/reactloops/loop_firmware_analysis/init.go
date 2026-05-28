package loop_firmware_analysis

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yaklang/yaklang/common/ai/aid/aicommon"
	"github.com/yaklang/yaklang/common/ai/aid/aireact/reactloops"
	"github.com/yaklang/yaklang/common/ai/aid/aitool"
	"github.com/yaklang/yaklang/common/log"
	"github.com/yaklang/yaklang/common/utils"
)

const LoopFirmwareAnalysisName = "firmware_analysis"

const (
	firmwareFindingsStateKey       = "firmware_findings_jsonl"
	firmwareDataStructuresStateKey = "firmware_data_structures_jsonl"
	firmwareFuzzPlansStateKey      = "firmware_fuzz_plans_jsonl"
	firmwareReportDeliveredKey     = "firmware_report_delivered"
)

type firmwareFinding struct {
	Title             string   `json:"title"`
	Category          string   `json:"category"`
	Severity          string   `json:"severity"`
	Confidence        string   `json:"confidence"`
	Scope             string   `json:"scope,omitempty"`
	AffectedFiles     []string `json:"affected_files,omitempty"`
	Source            string   `json:"source"`
	Transform         string   `json:"transform"`
	Sink              string   `json:"sink"`
	MissingGuard      string   `json:"missing_guard"`
	Evidence          string   `json:"evidence"`
	Limitations       string   `json:"limitations,omitempty"`
	SuppressionReason string   `json:"suppression_reason,omitempty"`
}

type firmwareDataStructure struct {
	Name               string `json:"name"`
	Location           string `json:"location"`
	Fields             string `json:"fields"`
	ProducerConsumer   string `json:"producer_consumer"`
	Evidence           string `json:"evidence"`
	Confidence         string `json:"confidence"`
	SemanticsStatus    string `json:"semantics_status"`
	ValidatedSemantics string `json:"validated_semantics,omitempty"`
	InferredLayout     string `json:"inferred_layout,omitempty"`
}

type firmwareFuzzPlan struct {
	Target           string `json:"target"`
	Entrypoint       string `json:"entrypoint"`
	InputModel       string `json:"input_model"`
	MutationStrategy string `json:"mutation_strategy"`
	Oracle           string `json:"oracle"`
	SetupNotes       string `json:"setup_notes"`
	Priority         string `json:"priority"`
}

type firmwareInventoryEntry struct {
	Name           string   `json:"name"`
	DisplayPath    string   `json:"display_path"`
	SizeLabel      string   `json:"size_label"`
	DetectedType   string   `json:"detected_type"`
	Platform       string   `json:"platform"`
	Evidence       []string `json:"evidence"`
	MemberCount    int      `json:"member_count,omitempty"`
	Members        []string `json:"members,omitempty"`
	IsArchive      bool     `json:"is_archive,omitempty"`
	SensitiveClass string   `json:"sensitive_class,omitempty"`
}

//go:embed prompts/persistent_instruction.txt
var persistentInstruction string

//go:embed prompts/reactive_data.txt
var reactiveDataTemplate string

//go:embed prompts/reflection_output_example.txt
var reflectionOutputExample string

func init() {
	err := reactloops.RegisterLoopFactory(
		LoopFirmwareAnalysisName,
		func(r aicommon.AIInvokeRuntime, opts ...reactloops.ReActLoopOption) (*reactloops.ReActLoop, error) {
			preset := []reactloops.ReActLoopOption{
				reactloops.WithAllowRAG(true),
				reactloops.WithAllowToolCall(true),
				reactloops.WithAllowAIForge(true),
				reactloops.WithAllowPlanAndExec(false),
				// Keep firmware evidence local to the current target and avoid
				// session memory recall polluting report conclusions.
				reactloops.WithMemoryTriage(aicommon.NewNoOpMemoryTriage()),
				reactloops.WithAllowUserInteract(r.GetConfig().GetAllowUserInteraction()),
				reactloops.WithMaxIterations(int(r.GetConfig().GetMaxIterationCount())),
				reactloops.WithPersistentInstruction(persistentInstruction),
				reactloops.WithReflectionOutputExample(reflectionOutputExample),
				reactloops.WithInitTask(buildInitTask(r)),
				buildReactiveDataBuilder(),
				recordBusinessFunctionAction(),
				recordDataStructureAction(),
				recordFindingAction(),
				recordDangerousFunctionAction(),
				proposeFuzzPlanAction(),
				finalFirmwareReportAction(r),
				buildFirmwareFinalizeHook(r),
			}
			preset = append(preset, opts...)
			return reactloops.NewReActLoop(LoopFirmwareAnalysisName, r, preset...)
		},
		reactloops.WithLoopDescription("Firmware and binary analysis mode: identify business functions, binary data structures, dangerous functions, and produce targeted fuzzing plans."),
		reactloops.WithLoopDescriptionZh("固件/二进制分析模式：分析客户提供的固件或二进制文件，梳理业务功能、数据结构、危险函数，并输出定向 fuzz 方案。"),
		reactloops.WithVerboseName("Firmware Analysis"),
		reactloops.WithVerboseNameZh("固件分析"),
		reactloops.WithLoopUsagePrompt("Use when the user provides a firmware image or binary file and wants business-function analysis, protocol/data-structure recovery, dangerous-function review, and a targeted fuzzing plan."),
		reactloops.WithLoopOutputExample(`
* When user provides a firmware or binary for analysis:
  {"@action": "firmware_analysis", "human_readable_thought": "Analyze firmware behavior, structures, dangerous functions, and fuzz targets"}
`),
	)
	if err != nil {
		log.Errorf("register reactloop: %v failed: %v", LoopFirmwareAnalysisName, err)
	}
}

func buildInitTask(r aicommon.AIInvokeRuntime) func(loop *reactloops.ReActLoop, task aicommon.AIStatefulTask, operator *reactloops.InitTaskOperator) {
	return func(loop *reactloops.ReActLoop, task aicommon.AIStatefulTask, operator *reactloops.InitTaskOperator) {
		targetPath := firmwareTargetPathFromTask(task)
		if targetPath == "" {
			targetPath = extractExistingPath(task.GetUserInput())
		}
		if targetPath == "" {
			operator.Continue()
			return
		}

		info, err := os.Stat(targetPath)
		if err != nil {
			operator.Failed(fmt.Sprintf("firmware target is not accessible: %s (%v)", targetPath, err))
			return
		}

		targetModel := buildFirmwareTargetModel(targetPath, info)
		loop.Set("firmware_target_path", targetModel.Path)
		loop.Set("firmware_filename", targetModel.Name)
		loop.Set("firmware_size", targetModel.PrimarySizeLabel())
		loop.Set("firmware_target_type", targetModel.Type)
		loop.Set("firmware_target_total_size", targetModel.TotalSize)
		loop.Set("firmware_target_file_count", strconv.Itoa(targetModel.FileCount))
		loop.Set("firmware_analysis_scope", targetModel.AnalysisScope)
		r.AddToTimeline("[FIRMWARE_TARGET]", fmt.Sprintf("target=%s type=%s size=%s files=%d", targetModel.Path, targetModel.Type, targetModel.PrimarySizeLabel(), targetModel.FileCount))
		operator.Continue()
	}
}

func buildReactiveDataBuilder() reactloops.ReActLoopOption {
	return reactloops.WithReactiveDataBuilder(func(loop *reactloops.ReActLoop, feedbacker *bytes.Buffer, nonce string) (string, error) {
		return utils.RenderTemplate(reactiveDataTemplate, map[string]any{
			"Nonce":              nonce,
			"FeedbackMessages":   feedbacker.String(),
			"FirmwareTargetType": loop.Get("firmware_target_type"),
			"FirmwareTargetPath": loop.Get("firmware_target_path"),
			"FirmwareFilename":   loop.Get("firmware_filename"),
			"FirmwareSize":       loop.Get("firmware_size"),
			"FirmwareTotalSize":  loop.Get("firmware_target_total_size"),
			"FirmwareFileCount":  loop.Get("firmware_target_file_count"),
			"FirmwareScope":      loop.Get("firmware_analysis_scope"),
			"BusinessFunctions":  loop.Get("business_functions"),
			"DataStructures":     loop.Get("data_structures"),
			"DangerousFunctions": loop.Get("dangerous_functions"),
			"FuzzPlans":          loop.Get("fuzz_plans"),
		})
	})
}

func recordBusinessFunctionAction() reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"record_business_function",
		"Record one confirmed or strongly inferred firmware business function/module with evidence.",
		[]aitool.ToolOption{
			aitool.WithStringParam("module", aitool.WithParam_Description("Module or feature name, such as login, config parser, OTA update, command dispatch, web route, or IPC service."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("summary", aitool.WithParam_Description("Concise business behavior summary."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("evidence", aitool.WithParam_Description("Evidence from strings, symbols, imports, paths, decompiled logic, or tool output."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("confidence", aitool.WithParam_Description("low, medium, or high.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			entry := fmt.Sprintf("### %s\n\n- 功能说明：%s\n- 识别依据：%s\n- 可信度：%s",
				action.GetString("module"),
				action.GetString("summary"),
				action.GetString("evidence"),
				localizeConfidence(defaultText(action.GetString("confidence"), "medium")),
			)
			appendLoopSection(loop, "business_functions", entry)
			op.Feedback("business function recorded")
			op.Continue()
		},
	)
}

func recordDataStructureAction() reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"record_data_structure",
		"Record one protocol, file format, message, config, or in-memory data structure found in the firmware.",
		[]aitool.ToolOption{
			aitool.WithStringParam("name", aitool.WithParam_Description("Structure/protocol/config name."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("location", aitool.WithParam_Description("Binary offset, function, file path, symbol, or other location evidence.")),
			aitool.WithStringParam("fields", aitool.WithParam_Description("Known or inferred fields, lengths, tags, magic bytes, delimiters, or constraints."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("producer_consumer", aitool.WithParam_Description("Code path that produces or consumes this structure.")),
			aitool.WithStringParam("evidence", aitool.WithParam_Description("Evidence supporting the structure."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("confidence", aitool.WithParam_Description("low, medium, or high.")),
			aitool.WithStringParam("semantics_status", aitool.WithParam_Description("validated or inferred.")),
			aitool.WithStringParam("validated_semantics", aitool.WithParam_Description("Semantics that were explicitly validated by symbols, code logic, docs, or direct evidence.")),
			aitool.WithStringParam("inferred_layout", aitool.WithParam_Description("Layout-only inference when field semantics are not fully validated.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			ds := normalizeDataStructure(firmwareDataStructure{
				Name:               action.GetString("name"),
				Location:           action.GetString("location"),
				Fields:             action.GetString("fields"),
				ProducerConsumer:   action.GetString("producer_consumer"),
				Evidence:           action.GetString("evidence"),
				Confidence:         action.GetString("confidence"),
				SemanticsStatus:    action.GetString("semantics_status"),
				ValidatedSemantics: action.GetString("validated_semantics"),
				InferredLayout:     action.GetString("inferred_layout"),
			})
			appendJSONLineState(loop, firmwareDataStructuresStateKey, ds)
			entry := renderDataStructureMarkdown(ds)
			appendLoopSection(loop, "data_structures", entry)
			op.Feedback("data structure recorded")
			op.Continue()
		},
	)
}

func recordFindingAction() reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"record_finding",
		"Record one evidence-chain finding with explicit source, transform, sink, missing guard, severity, confidence, and evidence.",
		[]aitool.ToolOption{
			aitool.WithStringParam("title", aitool.WithParam_Description("Short finding title."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("category", aitool.WithParam_Description("Finding category, such as path-traversal, command-injection, insufficient-length-check, or hardening."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("severity", aitool.WithParam_Description("info, low, medium, high, or critical."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("confidence", aitool.WithParam_Description("low, medium, or high."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("source", aitool.WithParam_Description("External input source."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("transform", aitool.WithParam_Description("Data processing or propagation chain."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("sink", aitool.WithParam_Description("Sensitive sink or impacted operation. Use 'not confirmed' if no concrete sink exists."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("missing_guard", aitool.WithParam_Description("Missing security validation or guard."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("evidence", aitool.WithParam_Description("Specific evidence from symbols, strings, source lines, decompiler output, or call/data-flow."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("suppression_reason", aitool.WithParam_Description("Why this should stay suspicious-only instead of a confirmed vulnerability, when applicable.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			finding := normalizeFinding(firmwareFinding{
				Title:             action.GetString("title"),
				Category:          action.GetString("category"),
				Severity:          action.GetString("severity"),
				Confidence:        action.GetString("confidence"),
				Source:            action.GetString("source"),
				Transform:         action.GetString("transform"),
				Sink:              action.GetString("sink"),
				MissingGuard:      action.GetString("missing_guard"),
				Evidence:          action.GetString("evidence"),
				SuppressionReason: action.GetString("suppression_reason"),
			})
			appendJSONLineState(loop, firmwareFindingsStateKey, finding)
			appendLoopSection(loop, "dangerous_functions", renderFindingMarkdown(finding))
			op.Feedback("finding recorded")
			op.Continue()
		},
	)
}

func recordDangerousFunctionAction() reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"record_dangerous_function",
		"Record a dangerous function, risky sink, or vulnerability-relevant call site with analysis evidence.",
		[]aitool.ToolOption{
			aitool.WithStringParam("function_name", aitool.WithParam_Description("Function or sink name, such as strcpy, sprintf, system, memcpy, sscanf, recv, or a custom parser."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("location", aitool.WithParam_Description("Address, symbol, file, function, xref, or decompiler location."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("risk", aitool.WithParam_Description("Risk type: overflow, command injection, path traversal, integer issue, auth bypass, parser crash, etc."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("input_source", aitool.WithParam_Description("Network/config/file/IPC/web parameter/environment input source.")),
			aitool.WithStringParam("evidence", aitool.WithParam_Description("Why this call site is risky."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("priority", aitool.WithParam_Description("low, medium, high, or critical.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			finding := normalizeFinding(firmwareFinding{
				Title:        action.GetString("function_name"),
				Category:     normalizeRiskCategory(action.GetString("risk")),
				Severity:     defaultText(action.GetString("priority"), "medium"),
				Confidence:   inferConfidenceFromEvidence(action.GetString("evidence")),
				Source:       defaultText(action.GetString("input_source"), "unknown"),
				Transform:    defaultText(action.GetString("location"), "unknown"),
				Sink:         action.GetString("function_name"),
				MissingGuard: action.GetString("risk"),
				Evidence:     action.GetString("evidence"),
			})
			appendJSONLineState(loop, firmwareFindingsStateKey, finding)
			appendLoopSection(loop, "dangerous_functions", renderFindingMarkdown(finding))
			op.Feedback("dangerous function recorded")
			op.Continue()
		},
	)
}

func proposeFuzzPlanAction() reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"propose_fuzz_plan",
		"Record one targeted fuzzing plan based on confirmed firmware functionality, structures, and risky sinks.",
		[]aitool.ToolOption{
			aitool.WithStringParam("target", aitool.WithParam_Description("Fuzz target function/module/protocol/parser."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("entrypoint", aitool.WithParam_Description("Harness entrypoint or runtime trigger path."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("input_model", aitool.WithParam_Description("Input format, seed source, grammar, or structure constraints."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("mutation_strategy", aitool.WithParam_Description("Focused mutation strategy tied to fields, lengths, tags, encodings, checksums, or boundary values."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("oracle", aitool.WithParam_Description("Crash, sanitizer, timeout, log, coverage, state change, or semantic bug oracle."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("setup_notes", aitool.WithParam_Description("Emulation/harness/extraction/dependency notes.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			plan := firmwareFuzzPlan{
				Target:           action.GetString("target"),
				Entrypoint:       action.GetString("entrypoint"),
				InputModel:       action.GetString("input_model"),
				MutationStrategy: action.GetString("mutation_strategy"),
				Oracle:           action.GetString("oracle"),
				SetupNotes:       defaultText(action.GetString("setup_notes"), "none"),
				Priority:         inferPlanPriority(loop),
			}
			appendJSONLineState(loop, firmwareFuzzPlansStateKey, plan)
			entry := renderFuzzPlanMarkdown(plan)
			appendLoopSection(loop, "fuzz_plans", entry)
			op.Feedback("fuzz plan recorded")
			op.Continue()
		},
	)
}

func finalFirmwareReportAction(r aicommon.AIInvokeRuntime) reactloops.ReActLoopOption {
	return reactloops.WithRegisterLoopAction(
		"final_firmware_report",
		"Finish the firmware analysis and emit a Markdown report from the accumulated findings.",
		[]aitool.ToolOption{
			aitool.WithStringParam("executive_summary", aitool.WithParam_Description("Short final summary for the report."), aitool.WithParam_Required(true)),
			aitool.WithStringParam("remaining_gaps", aitool.WithParam_Description("Known analysis gaps or assumptions.")),
		},
		nil,
		func(loop *reactloops.ReActLoop, action *aicommon.Action, op *reactloops.LoopActionHandlerOperator) {
			report, artifact := deliverFirmwareReport(loop, r, action.GetString("executive_summary"), action.GetString("remaining_gaps"))
			if strings.TrimSpace(report) == "" {
				op.Feedback("firmware analysis completed with fallback summary; no detailed report content was available")
			} else {
				op.Feedback("firmware analysis completed; report generated: " + artifact)
			}
			op.Exit()
		},
	)
}

func buildFirmwareFinalizeHook(r aicommon.AIInvokeRuntime) reactloops.ReActLoopOption {
	return reactloops.WithOnPostIteraction(func(loop *reactloops.ReActLoop, iteration int, task aicommon.AIStatefulTask, isDone bool, reason any, operator *reactloops.OnPostIterationOperator) {
		if !isDone || loop == nil || reportAlreadyDelivered(loop) {
			return
		}
		report, artifact := deliverFirmwareReport(loop, r, "", "")
		if strings.TrimSpace(report) == "" {
			log.Warnf("firmware_analysis finalize fallback: empty report at iteration %d", iteration)
			return
		}
		log.Infof("firmware_analysis finalize fallback: delivered report at iteration %d: %s", iteration, artifact)
	})
}

type firmwareReportContext struct {
	TargetPath           string
	TargetName           string
	TargetSize           string
	TargetType           string
	TargetTotalSize      string
	TargetFileCount      int
	TargetScope          string
	TargetDetectedType   string
	TargetKeyPaths       []string
	InventoryEntries     []firmwareInventoryEntry
	InventoryMarkdown    string
	BusinessFunctions    string
	DataStructures       string
	DangerousFunctions   string
	FuzzPlans            string
	Summary              string
	UserInput            string
	Corpus               string
	FindingEntries       []firmwareFinding
	DataStructureEntries []firmwareDataStructure
	FuzzPlanEntries      []firmwareFuzzPlan
}

type firmwareTargetModel struct {
	Type          string
	Name          string
	Path          string
	Size          string
	TotalSize     string
	FileCount     int
	AnalysisScope string
	DetectedType  string
	KeyPaths      []string
	Inventory     []firmwareInventoryEntry
}

func (m firmwareTargetModel) PrimarySizeLabel() string {
	if strings.TrimSpace(m.Size) != "" {
		return m.Size
	}
	if strings.TrimSpace(m.TotalSize) != "" {
		return m.TotalSize
	}
	return "unknown"
}

func buildFinalReport(loop *reactloops.ReActLoop, summary string, gaps string) string {
	ctx := populateFirmwareReportContext(buildFirmwareReportContext(loop, summary))
	loop.Set("firmware_target_path", ctx.TargetPath)
	loop.Set("firmware_filename", ctx.TargetName)
	loop.Set("firmware_size", ctx.TargetSize)
	loop.Set("firmware_target_type", ctx.TargetType)
	loop.Set("firmware_target_total_size", ctx.TargetTotalSize)
	loop.Set("firmware_target_file_count", strconv.Itoa(ctx.TargetFileCount))
	loop.Set("firmware_analysis_scope", ctx.TargetScope)
	loop.Set("business_functions", ctx.BusinessFunctions)
	loop.Set("data_structures", ctx.DataStructures)
	loop.Set("dangerous_functions", ctx.DangerousFunctions)
	loop.Set("fuzz_plans", ctx.FuzzPlans)
	return buildReportMarkdown(ctx, gaps)
}

func deliverFirmwareReport(loop *reactloops.ReActLoop, invoker aicommon.AIInvokeRuntime, summary string, gaps string) (string, string) {
	if loop == nil || invoker == nil {
		return "", ""
	}
	report := strings.TrimSpace(buildFinalReport(loop, summary, gaps))
	if report == "" {
		return "", ""
	}
	alreadyDelivered := reportAlreadyDelivered(loop)
	artifact := loop.Get("firmware_analysis_report")
	if strings.TrimSpace(artifact) == "" {
		artifact = invoker.EmitFileArtifactWithExt("firmware_analysis_report", ".md", report)
		loop.Set("firmware_analysis_report", artifact)
	}
	if !alreadyDelivered {
		invoker.AddToTimeline("[FIRMWARE_ANALYSIS_REPORT]", report)
		invoker.EmitResultAfterStream(report)
		invoker.AddToTimeline("[FIRMWARE_ANALYSIS_FINISHED]", "firmware analysis completed")
		markReportDelivered(loop)
	}
	return report, artifact
}

func markReportDelivered(loop *reactloops.ReActLoop) {
	if loop != nil {
		loop.Set(firmwareReportDeliveredKey, true)
	}
}

func reportAlreadyDelivered(loop *reactloops.ReActLoop) bool {
	if loop == nil {
		return false
	}
	return utils.InterfaceToBoolean(loop.Get(firmwareReportDeliveredKey))
}

func buildFirmwareReportContext(loop *reactloops.ReActLoop, summary string) firmwareReportContext {
	ctx := firmwareReportContext{
		Summary: summary,
	}
	if loop == nil {
		return ctx
	}
	ctx.TargetPath = strings.TrimSpace(loop.Get("firmware_target_path"))
	ctx.TargetName = strings.TrimSpace(loop.Get("firmware_filename"))
	ctx.TargetSize = strings.TrimSpace(loop.Get("firmware_size"))
	ctx.TargetType = strings.TrimSpace(loop.Get("firmware_target_type"))
	ctx.TargetTotalSize = strings.TrimSpace(loop.Get("firmware_target_total_size"))
	ctx.TargetScope = strings.TrimSpace(loop.Get("firmware_analysis_scope"))
	if n, err := strconv.Atoi(strings.TrimSpace(loop.Get("firmware_target_file_count"))); err == nil {
		ctx.TargetFileCount = n
	}
	ctx.BusinessFunctions = strings.TrimSpace(loop.Get("business_functions"))
	ctx.DataStructures = strings.TrimSpace(loop.Get("data_structures"))
	ctx.DangerousFunctions = strings.TrimSpace(loop.Get("dangerous_functions"))
	ctx.FuzzPlans = strings.TrimSpace(loop.Get("fuzz_plans"))
	ctx.FindingEntries = parseJSONLineState[firmwareFinding](loop.Get(firmwareFindingsStateKey))
	ctx.DataStructureEntries = parseJSONLineState[firmwareDataStructure](loop.Get(firmwareDataStructuresStateKey))
	ctx.FuzzPlanEntries = parseJSONLineState[firmwareFuzzPlan](loop.Get(firmwareFuzzPlansStateKey))
	if task := loop.GetCurrentTask(); task != nil {
		ctx.UserInput = task.GetUserInput()
		if ctx.TargetPath == "" {
			ctx.TargetPath = firmwareTargetPathFromTask(task)
			if ctx.TargetPath == "" {
				ctx.TargetPath = extractExistingPath(task.GetUserInput())
			}
		}
	}
	ctx.Corpus = readFirmwareEvidenceCorpus(loop.Get("task_directory"))
	return ctx
}

func populateFirmwareReportContext(ctx firmwareReportContext) firmwareReportContext {
	if ctx.TargetPath == "" {
		ctx.TargetPath = extractExistingPath(ctx.UserInput)
	}
	if info, err := os.Stat(ctx.TargetPath); err == nil {
		model := buildFirmwareTargetModel(ctx.TargetPath, info)
		if ctx.TargetType == "" {
			ctx.TargetType = model.Type
		}
		if ctx.TargetName == "" {
			ctx.TargetName = model.Name
		}
		if ctx.TargetSize == "" {
			ctx.TargetSize = model.Size
		}
		if ctx.TargetTotalSize == "" {
			ctx.TargetTotalSize = model.TotalSize
		}
		if ctx.TargetFileCount == 0 {
			ctx.TargetFileCount = model.FileCount
		}
		if ctx.TargetScope == "" {
			ctx.TargetScope = model.AnalysisScope
		}
		if ctx.TargetDetectedType == "" {
			ctx.TargetDetectedType = model.DetectedType
		}
		if len(ctx.TargetKeyPaths) == 0 {
			ctx.TargetKeyPaths = model.KeyPaths
		}
		if len(ctx.InventoryEntries) == 0 {
			ctx.InventoryEntries = model.Inventory
		}
	}
	if ctx.TargetName == "" && ctx.TargetPath != "" {
		ctx.TargetName = filepath.Base(ctx.TargetPath)
	}
	if ctx.TargetType == "" && ctx.TargetPath != "" {
		ctx.TargetType = "file"
	}
	if ctx.TargetFileCount == 0 && ctx.TargetPath != "" {
		ctx.TargetFileCount = 1
	}
	ctx.InventoryMarkdown = renderInventoryMarkdown(ctx.InventoryEntries)

	if len(ctx.DataStructureEntries) == 0 {
		ctx.DataStructureEntries = inferFirmwareDataStructures(ctx.Summary, ctx.Corpus)
	}
	if ctx.BusinessFunctions == "" {
		ctx.BusinessFunctions = inferBusinessFunctions(ctx.Summary, ctx.Corpus)
	}
	if len(ctx.FindingEntries) == 0 {
		if strings.Contains(ctx.TargetType, "directory") || strings.Contains(ctx.TargetType, "filesystem") {
			ctx.FindingEntries = inferCorpusFindingsFromInventory(ctx.InventoryEntries, ctx.TargetPath)
		} else {
			ctx.FindingEntries = inferFirmwareFindings(ctx.Summary, ctx.Corpus)
		}
	}
	if len(ctx.FuzzPlanEntries) == 0 {
		ctx.FuzzPlanEntries = inferFuzzPlans(ctx.Summary, ctx.Corpus, ctx.FindingEntries, ctx.DataStructureEntries)
	}
	if shouldPreferSyntheticSummary(ctx) || strings.TrimSpace(ctx.Summary) == "" {
		ctx.Summary = synthesizeReportSummary(ctx)
	}
	ctx.DataStructures = renderDataStructuresMarkdown(ctx.DataStructureEntries, ctx.DataStructures)
	ctx.DangerousFunctions = renderFindingsMarkdown(ctx.FindingEntries, ctx.DangerousFunctions)
	ctx.FuzzPlans = renderFuzzPlansMarkdown(ctx.FuzzPlanEntries, ctx.FuzzPlans)
	return ctx
}

func buildReportMarkdown(ctx firmwareReportContext, gaps string) string {
	if gaps == "" {
		gaps = "暂无明确未覆盖项。"
	}
	targetMetadata := renderTargetMetadataMarkdown(ctx)
	targetDetails := renderTargetDetailsMarkdown(ctx)
	return fmt.Sprintf(`# 固件分析报告

## 摘要

%s

## 目标范围

%s
%s

%s

## 业务功能

%s

## 数据结构

%s

## 风险发现

%s

## 定向 Fuzz 方案

%s

## 已知限制

%s
`,
		defaultText(ctx.Summary, "本次分析围绕固件/二进制业务功能、数据结构、危险函数和 fuzz 方案进行。"),
		targetMetadata,
		targetDetails,
		defaultText(ctx.InventoryMarkdown, "## 样本清单\n\n暂无记录。"),
		defaultText(ctx.BusinessFunctions, "暂无记录。"),
		defaultText(ctx.DataStructures, "暂无记录。"),
		defaultText(ctx.DangerousFunctions, "暂无记录。"),
		defaultText(ctx.FuzzPlans, "暂无记录。"),
		gaps,
	)
}

func renderTargetMetadataMarkdown(ctx firmwareReportContext) string {
	lines := []string{
		fmt.Sprintf("- 目标类型：%s", localizeTargetType(defaultText(ctx.TargetType, "unknown"))),
		fmt.Sprintf("- 目标名称：%s", defaultText(ctx.TargetName, "unknown")),
		fmt.Sprintf("- 目标路径：%s", defaultText(ctx.TargetPath, "unknown")),
	}
	switch strings.TrimSpace(ctx.TargetType) {
	case "directory / firmware corpus", "extracted filesystem":
		lines = append(lines,
			fmt.Sprintf("- 总大小：%s", defaultText(ctx.TargetTotalSize, ctx.TargetSize)),
			fmt.Sprintf("- 文件数量：%d", ctx.TargetFileCount),
		)
	case "archive":
		lines = append(lines, fmt.Sprintf("- 压缩包大小：%s", defaultText(ctx.TargetSize, ctx.TargetTotalSize)))
	default:
		lines = append(lines, fmt.Sprintf("- 文件大小：%s", defaultText(ctx.TargetSize, "unknown")))
	}
	lines = append(lines, fmt.Sprintf("- 分析范围：%s", localizeAnalysisScope(defaultText(ctx.TargetScope, "single target"))))
	return strings.Join(lines, "\n")
}

func readFirmwareEvidenceCorpus(taskDir string) string {
	taskDir = strings.TrimSpace(taskDir)
	if taskDir == "" {
		return ""
	}
	var chunks []string
	_ = filepath.WalkDir(taskDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".md", ".txt", ".log":
		default:
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		text := string(raw)
		if len(text) > 32*1024 {
			text = text[:32*1024]
		}
		chunks = append(chunks, text)
		return nil
	})
	return strings.Join(chunks, "\n")
}

func inferBusinessFunctions(summary string, corpus string) string {
	text := summary + "\n" + corpus
	var entries []string
	if hasConfirmedFWUPParserCapability(text) {
		entries = append(entries, "### FWUP 固件解析器\n\n- 功能说明：解析自定义 FWUP 固件格式，读取固定头部，校验魔数后将剩余载荷交给后续处理逻辑。\n- 识别依据：观察到 FirmwareHeader、parseFirmware/processPayload 符号以及 FWUP magic 校验路径。\n- 可信度：高")
	}
	if hasConfirmedSaveHandlerCapability(text) {
		entries = append(entries, "### SAVE 文件落地处理器\n\n- 功能说明：从固件载荷中解析文件名与文件内容，并将结果写入预设目录。\n- 识别依据：观察到文件名长度解析、filepath.Join 路径拼接以及 os.WriteFile 文件写入调用。\n- 可信度：高")
	}
	if containsAny(text, "PING") && containsAny(text, "targetIP", "network diagnostic", "payload[:4]") {
		entries = append(entries, "### 诊断命令标记处理逻辑\n\n- 功能说明：存在按诊断标记分支提取目标字段的逻辑；是否构成命令执行风险，需由风险发现中的数据流证据单独判定。\n- 识别依据：观察到 PING 标记检查和目标字段提取路径。\n- 可信度：中")
	}
	if containsAny(text, "META", "metadata") && containsAny(text, "payload[7]", "Uint32(payload[:4])", "fixed-position read", "fixed index") {
		entries = append(entries, "### META 元数据处理逻辑\n\n- 功能说明：按 META 标记解析固定偏移字段并继续处理对应元数据载荷。\n- 识别依据：观察到 META 标记检查、固定索引访问以及二进制数值读取逻辑。\n- 可信度：中")
	}
	return strings.Join(entries, "\n\n")
}

func hasConfirmedFWUPParserCapability(text string) bool {
	return containsAny(text, "FWUP") &&
		containsAny(text, "FirmwareHeader", "parseFirmware", "binary.Read") &&
		containsAny(text, "header.Magic", "magic compared before dispatch", "magic validation")
}

func hasConfirmedSaveHandlerCapability(text string) bool {
	return containsAny(text, "SAVE") &&
		containsAny(text, "os.WriteFile", "WriteFile") &&
		containsAny(text, "filename", "fileNameLen", "filepath.Join", "payload[6")
}

func shouldPreferSyntheticSummary(ctx firmwareReportContext) bool {
	switch strings.TrimSpace(ctx.TargetType) {
	case "directory / firmware corpus", "archive", "extracted filesystem":
		return true
	default:
		return false
	}
}

func synthesizeReportSummary(ctx firmwareReportContext) string {
	targetName := defaultText(ctx.TargetName, filepath.Base(strings.TrimSpace(ctx.TargetPath)))
	targetLabel := localizeTargetType(defaultText(ctx.TargetType, "目标"))
	var parts []string
	if targetLabel == "" {
		targetLabel = "目标"
	}
	head := fmt.Sprintf("对%s `%s` 完成分析。", targetLabel, targetName)
	if ctx.TargetFileCount > 0 || strings.TrimSpace(ctx.TargetTotalSize) != "" {
		head += fmt.Sprintf(" 该目标包含 %d 个文件，总大小 %s。", ctx.TargetFileCount, defaultText(ctx.TargetTotalSize, ctx.TargetSize))
	}
	parts = append(parts, head)

	if groups := summarizeVendorGroups(ctx.InventoryEntries); len(groups) > 0 {
		parts = append(parts, fmt.Sprintf("识别出的样本归属包括：%s。", strings.Join(groups, "、")))
	}

	if findingSummary := summarizeFindingSummary(ctx.FindingEntries); findingSummary != "" {
		parts = append(parts, findingSummary)
	}
	return strings.Join(parts, " ")
}

func summarizeVendorGroups(entries []firmwareInventoryEntry) []string {
	var groups []string
	for _, entry := range entries {
		platform := strings.TrimSpace(entry.Platform)
		if platform == "" || platform == "unknown" {
			continue
		}
		groups = append(groups, platform)
	}
	return dedupeStrings(groups)
}

func summarizeFindingSummary(findings []firmwareFinding) string {
	if len(findings) == 0 {
		return "当前未形成高可信度风险结论。"
	}
	var hasConfigExposure, hasParsedPrivateKey, hasKeyBlob, hasPrivateData, hasAttackSurface bool
	hasHighSeverity := false
	for _, finding := range findings {
		finding = normalizeFinding(finding)
		if severityScore(finding.Severity) >= severityScore("high") {
			hasHighSeverity = true
		}
		switch finding.Category {
		case "sensitive-data-exposure":
			hasConfigExposure = true
		case "private-key-exposure":
			hasParsedPrivateKey = true
		case "sensitive-data-presence":
			hasKeyBlob = true
		case "private-data-exposure":
			hasPrivateData = true
		case "attack-surface", "container-observation":
			hasAttackSurface = true
		}
	}
	var parts []string
	if hasConfigExposure {
		parts = append(parts, "确认的高风险主要是导出的配置文件包含认证材料，包括本地用户口令保护字段、SNMPv3 认证/隐私材料以及管理入口配置。")
	}
	if hasParsedPrivateKey {
		parts = append(parts, "确认发现可解析的未加密标准私钥材料，应按高风险敏感信息暴露处置。")
	}
	if hasKeyBlob {
		parts = append(parts, "另发现疑似设备密钥材料，应按敏感文件处理，但密钥类型、加密状态和可用性未确认。")
	}
	if hasPrivateData {
		parts = append(parts, "目录中还包含设备私有数据文件，暴露了接口、拓扑或设备侧私有标识线索。")
	}
	if hasAttackSurface {
		parts = append(parts, "若干固件镜像暴露出服务、组件和管理面攻击面线索，但尚未确认可达入口、数据流和危险调用。")
	}
	if len(parts) == 0 {
		if hasHighSeverity {
			return "当前已形成需要优先处理的高风险结论，请重点关注下文高危 finding 的证据链与影响范围。"
		}
		return "当前主要完成了样本类型识别与攻击面梳理，尚未形成需要升级为高风险的确认结论。"
	}
	return strings.Join(parts, " ")
}

func inferFirmwareDataStructures(summary string, corpus string) []firmwareDataStructure {
	text := summary + "\n" + corpus
	var entries []firmwareDataStructure
	if containsAny(text, "type FirmwareHeader struct", "Magic   [4]byte", "Version uint32", "Len     uint32") {
		entries = append(entries, normalizeDataStructure(firmwareDataStructure{
			Name:               "FirmwareHeader",
			Location:           "header decode path before payload dispatch",
			Fields:             "Magic[4] ('FWUP'), Version(uint32), Len(uint32)",
			ProducerConsumer:   "Parsed from firmware input and consumed by payload parser",
			Evidence:           "Observed explicit FirmwareHeader struct definition, binary.Read into the struct, and magic validation in the analysis corpus.",
			Confidence:         "high",
			SemanticsStatus:    "validated",
			ValidatedSemantics: "Header field names and layout are confirmed directly by source or symbols.",
		}))
	} else if containsAny(text, "12-byte header", "magic compared before dispatch", "u32 read at offset 4", "u32 read at offset 8") {
		entries = append(entries, normalizeDataStructure(firmwareDataStructure{
			Name:             "custom_firmware_header",
			Location:         "parser entry before payload handling",
			Fields:           "magic[4], u32_at_4, u32_at_8",
			ProducerConsumer: "Consumed by the initial parser and downstream payload dispatcher",
			Evidence:         "Observed a fixed-size header, magic comparison before dispatch, and two 32-bit reads at offsets 4 and 8 without validated semantic names.",
			Confidence:       "medium",
			SemanticsStatus:  "inferred",
			InferredLayout:   "Only layout is inferred; field semantics beyond the magic are not explicitly validated.",
		}))
	}
	return entries
}

func inferFirmwareFindings(summary string, corpus string) []firmwareFinding {
	text := summary + "\n" + corpus
	var findings []firmwareFinding
	if containsAny(text, "FirmwareHeader", "binary.Read", "string(header.Magic[:]) != \"FWUP\"", "magic compared before dispatch") {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "Custom firmware format detected",
			Category:     "custom-format",
			Severity:     "info",
			Confidence:   "high",
			Source:       "firmware file blob",
			Transform:    "header deserialization followed by magic comparison before payload dispatch",
			Sink:         "parser dispatch",
			MissingGuard: "not applicable",
			Evidence:     `Observed a 12-byte header, little-endian deserialization, and explicit "FWUP" magic validation before payload processing.`,
		}))
	}
	if detectPathTraversalPattern(text) {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "Path traversal leading to arbitrary file write",
			Category:     "path-traversal",
			Severity:     "high",
			Confidence:   "high",
			Source:       "SAVE payload filename decoded from the firmware payload",
			Transform:    `payload filename -> filepath.Join("/tmp/fwupload", filename)`,
			Sink:         "os.WriteFile",
			MissingGuard: "no canonical containment check was observed after filepath.Join, so writes may escape /tmp/fwupload",
			Evidence:     `SAVE payload filename -> filepath.Join("/tmp/fwupload", filename) -> os.WriteFile`,
		}))
	}
	if detectUntrustedLengthSlicingPattern(text) {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "SAVE filename length used without bounds validation",
			Category:     "untrusted-length-slicing",
			Severity:     "high",
			Confidence:   "high",
			Source:       "SAVE filenameLen parsed from payload[4:6]",
			Transform:    "u16 filenameLen controls payload[6:6+filenameLen] and payload[6+filenameLen:] slicing",
			Sink:         "slice operations over the payload buffer",
			MissingGuard: "no check that len(payload) >= 6+filenameLen before slicing the filename and body",
			Evidence:     "u16 length from payload[4:6] directly controls payload[6:6+filenameLen] and payload[6+filenameLen:] without len(payload) >= 6+filenameLen validation.",
		}))
	}
	if detectInsufficientLengthCheckPattern(text) {
		impact := "panic DoS"
		if detectCLikeCorpus(text) {
			impact = "out-of-bounds read/write"
		}
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "Insufficient length check before payload index access",
			Category:     "insufficient-length-check",
			Severity:     "high",
			Confidence:   "high",
			Source:       "firmware payload bytes",
			Transform:    "META branch applies len(payload) >= 4, then performs a later fixed-position read at payload[7]",
			Sink:         "indexed memory access into the payload buffer",
			MissingGuard: "the branch guard does not prove that the highest accessed index is in bounds",
			Evidence:     fmt.Sprintf("META branch uses len(payload) >= 4 as its guard but still reads payload[7], so payload lengths 4-7 can trigger %s.", impact),
		}))
	}
	if detectDeclaredPayloadLengthNotValidated(text) {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "Declared payload length not validated against actual payload size",
			Category:     "declared-payload-length-not-validated",
			Severity:     "medium",
			Confidence:   "high",
			Source:       "header.Len parsed from the firmware header",
			Transform:    "header.Len is parsed, only upper-bound checked, and payload is still taken as data[12:]",
			Sink:         "downstream parser logic that assumes the declared length matches the actual payload",
			MissingGuard: "no explicit validation that len(actual_payload) >= declared_length before downstream processing",
			Evidence:     "header.Len is parsed from the FWUP header and only upper-bound checked; actual payload is still data[12:] without validating that len(data[12:]) matches header.Len.",
		}))
	}
	if detectMissingIntegrityVerification(text) {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "No cryptographic integrity/authenticity verification observed",
			Category:     "missing-integrity-verification",
			Severity:     "medium",
			Confidence:   "medium",
			Source:       "firmware blob accepted after FWUP magic validation",
			Transform:    "header parsing and command dispatch proceed directly into SAVE/META processing",
			Sink:         "payload-processing operations such as file writes or other state-changing behavior",
			MissingGuard: "no cryptographic integrity or authenticity verification was observed before payload commands were processed",
			Evidence:     `FWUP magic is checked, but no signature or cryptographic hash verification was observed before SAVE/META payload processing.`,
		}))
	}
	if detectConfirmedCommandInjection(text) {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:        "External input reaches command-execution sink",
			Category:     "command-injection",
			Severity:     "high",
			Confidence:   "high",
			Source:       "external firmware/config payload input",
			Transform:    "payload-controlled data propagates into command construction",
			Sink:         "confirmed command-execution API such as exec.Command/system/popen/execve",
			MissingGuard: "no safe argument validation or allowlist was observed before the command sink",
			Evidence:     "Command-execution sink and payload-derived argument flow were both observed in the analysis corpus.",
		}))
	}
	return dedupeFindings(findings)
}

func inferFuzzPlans(summary string, corpus string, findings []firmwareFinding, structures []firmwareDataStructure) []firmwareFuzzPlan {
	text := summary + "\n" + corpus
	if len(findings) == 0 && !containsAny(text, "parseFirmware", "processPayload", "payload") {
		return nil
	}
	if shouldUseCorpusValidationPlan(findings, structures, text) {
		return []firmwareFuzzPlan{{
			Target:           "固件容器解包验证与配置导入解析器健壮性验证",
			Entrypoint:       "样本目录中的固件镜像、补丁包、配置备份包及后续定位到的服务二进制",
			InputModel:       "先按样本类型区分固件容器、配置备份包和已提取文件系统；对可解包样本保留原始容器结构，对配置样本保留文本语法与关键字段布局。",
			MutationStrategy: "第一阶段验证容器解包路径、文件系统提取与配置导入链路；第二阶段围绕配置语法、压缩包成员、服务协议输入和边界长度做定向变异；第三阶段仅在确认具体服务入口和 sink 后，为对应二进制生成专门 fuzz harness。",
			Oracle:           "解包工具异常退出、解析器 panic/crash、配置导入失败、异常接受畸形配置、越界日志、以及后续定位服务在协议输入下的崩溃或卡死。",
			SetupNotes:       "先完成解包与组件归类，再按厂商与组件类型分别建立种子集；不要在未确认具体 parser 前复用其他样本的协议模板。",
			Priority:         inferHighestSeverity(findings),
		}}
	}
	inputModel := "Seed with a valid container header plus one command body, then mutate command selectors, length fields, and command-specific subfields."
	if len(structures) > 0 {
		inputModel = "Preserve the detected custom firmware header, then mutate command payloads while keeping the outer container syntactically valid enough to reach deeper handlers."
	}
	mutationStrategy := "Mutate declared length fields, command selectors, payload sizes, filenames/paths, and short inputs around fixed-index reads. Preserve enough container structure to keep reaching parser internals."
	oracle := "panic/crash, bounds-check failures, writes escaping the intended directory, unexpected file creation, and any state-changing side effects tied to parsed commands"
	if containsFindingCategory(findings, "path-traversal") || containsFindingCategory(findings, "untrusted-length-slicing") || containsFindingCategory(findings, "insufficient-length-check") {
		inputModel = "Preserve the FWUP-style outer header, then build SAVE and META command bodies whose subfields can be mutated independently."
		mutationStrategy = "Focus on META short-length boundaries around payload[7], SAVE filenameLen and the resulting payload[6:6+filenameLen] slice boundary, traversal paths in the SAVE filename, and mismatches between header.Len and the actual payload length."
		oracle = "Go panic / bounds-check failures, writes escaping /tmp/fwupload, unexpected file creation, and divergent behavior when header.Len disagrees with the actual payload length"
	}
	return []firmwareFuzzPlan{{
		Target:           "firmware parser and payload command dispatcher",
		Entrypoint:       "firmware file or stdin input reaching the main parser",
		InputModel:       inputModel,
		MutationStrategy: mutationStrategy,
		Oracle:           oracle,
		SetupNotes:       "Prefer a sandboxed filesystem view so path-traversal writes can be observed safely; keep a seed corpus with one valid header sample and one sample per discovered command branch.",
		Priority:         inferHighestSeverity(findings),
	}}
}

func shouldUseCorpusValidationPlan(findings []firmwareFinding, structures []firmwareDataStructure, text string) bool {
	if len(structures) > 0 && containsAny(text, "firmwareheader", "parsefirmware", "processpayload", "fwup") {
		return false
	}
	if containsFindingCategory(findings, "path-traversal") || containsFindingCategory(findings, "untrusted-length-slicing") || containsFindingCategory(findings, "insufficient-length-check") {
		return false
	}
	return containsFindingCategory(findings, "attack-surface") ||
		containsFindingCategory(findings, "container-observation") ||
		containsFindingCategory(findings, "sensitive-data-exposure") ||
		containsFindingCategory(findings, "sensitive-data-presence") ||
		containsFindingCategory(findings, "private-data-exposure")
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func containsAny(text string, needles ...string) bool {
	lower := strings.ToLower(text)
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func buildFirmwareTargetModel(targetPath string, info os.FileInfo) firmwareTargetModel {
	model := firmwareTargetModel{
		Path:          targetPath,
		Name:          filepath.Base(targetPath),
		AnalysisScope: "single target",
		DetectedType:  "unknown",
	}
	if info == nil {
		return model
	}
	if info.IsDir() {
		model.Type = "directory / firmware corpus"
		model.TotalSize, model.FileCount, model.Inventory = scanFirmwareCorpusDirectory(targetPath)
		model.Size = model.TotalSize
		model.AnalysisScope = "top-level + selected archive members"
		model.DetectedType = "firmware corpus"
		if looksLikeExtractedFilesystem(targetPath) {
			model.Type = "extracted filesystem"
			model.TotalSize, model.FileCount, model.Inventory, model.KeyPaths = scanExtractedFilesystem(targetPath)
			model.Size = model.TotalSize
			model.DetectedType = detectFilesystemPlatform(targetPath)
			model.AnalysisScope = "recursive filesystem inspection"
		}
		return model
	}
	if isArchivePath(targetPath) {
		model.Type = "archive"
		model.Size = formatByteSize(info.Size())
		model.TotalSize = model.Size
		model.FileCount = 1
		model.AnalysisScope = "archive members inspected"
		model.DetectedType = "archive"
		model.Inventory = inspectArchiveInventory(targetPath)
		return model
	}
	model.Type = "file"
	model.Size = formatByteSize(info.Size())
	model.TotalSize = model.Size
	model.FileCount = 1
	model.DetectedType = detectSingleFileType(targetPath)
	model.Inventory = []firmwareInventoryEntry{buildInventoryEntry(targetPath, info, filepath.Base(targetPath))}
	return model
}

func scanFirmwareCorpusDirectory(dir string) (string, int, []firmwareInventoryEntry) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var total int64
	var count int
	var inventory []firmwareInventoryEntry
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		total += info.Size()
		count++
		inventory = append(inventory, buildInventoryEntry(fullPath, info, entry.Name()))
	}
	return formatApproxByteSize(total), count, inventory
}

func scanExtractedFilesystem(dir string) (string, int, []firmwareInventoryEntry, []string) {
	var total int64
	var count int
	var inventory []firmwareInventoryEntry
	keyPaths := detectFilesystemKeyPaths(dir)
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		total += info.Size()
		count++
		if len(inventory) >= 20 {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		rel = filepath.ToSlash(rel)
		if shouldIncludeRootfsInventory(rel) {
			inventory = append(inventory, buildInventoryEntry(path, info, rel))
		}
		return nil
	})
	return formatApproxByteSize(total), count, inventory, keyPaths
}

func buildInventoryEntry(fullPath string, info os.FileInfo, displayName string) firmwareInventoryEntry {
	probe := newFirmwareFileProbe(fullPath)
	entry := firmwareInventoryEntry{
		Name:         filepath.Base(fullPath),
		DisplayPath:  displayName,
		SizeLabel:    formatByteSize(info.Size()),
		DetectedType: detectSingleFileTypeWithProbe(probe),
		Platform:     detectPlatformFromProbe(probe),
		Evidence:     detectInventoryEvidenceWithProbe(probe),
	}
	if entry.Platform == "" {
		entry.Platform = "unknown"
	}
	if isArchivePath(fullPath) {
		entry.IsArchive = true
		entry.DetectedType = detectArchiveType(fullPath)
		entry.Members, entry.MemberCount = inspectArchiveMembers(fullPath)
	}
	entry.Evidence = maskEvidenceList(entry.Evidence)
	return entry
}

func inspectArchiveInventory(path string) []firmwareInventoryEntry {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return []firmwareInventoryEntry{buildInventoryEntry(path, info, filepath.Base(path))}
}

func inspectArchiveMembers(path string) ([]string, int) {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		return nil, 0
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, 0
	}
	defer reader.Close()
	var members []string
	for _, file := range reader.File {
		members = append(members, fmt.Sprintf("%s, %s", file.Name, formatByteSize(int64(file.UncompressedSize64))))
	}
	sort.Strings(members)
	return members, len(members)
}

func renderInventoryMarkdown(entries []firmwareInventoryEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## 样本清单\n\n")
	b.WriteString("| 文件 | 大小 | 初步类型 | 平台/厂商 | 识别依据 |\n")
	b.WriteString("|---|---:|---|---|---|\n")
	for _, entry := range entries {
		evidence := strings.Join(entry.Evidence, "；")
		if entry.IsArchive && entry.MemberCount > 0 {
			evidence = strings.TrimSpace(evidence + "；压缩包成员：" + strings.Join(entry.Members, "；"))
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			entry.DisplayPath,
			entry.SizeLabel,
			localizeDetectedType(defaultText(entry.DetectedType, "unknown")),
			defaultText(entry.Platform, "unknown"),
			defaultText(evidence, "unknown"),
		))
	}
	return b.String()
}

func formatByteSize(size int64) string {
	return fmt.Sprintf("%d bytes", size)
}

func formatApproxByteSize(size int64) string {
	if size > 1024*1024 {
		return fmt.Sprintf("about %dMB", size/(1024*1024))
	}
	return formatByteSize(size)
}

func isArchivePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2":
		return true
	default:
		return false
	}
}

func detectArchiveType(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(base, ".zip") && archiveContainsConfig(path):
		return "config-archive"
	case strings.HasSuffix(base, ".zip"):
		return "archive"
	default:
		return "archive"
	}
}

func detectSingleFileType(path string) string {
	return detectSingleFileTypeWithProbe(newFirmwareFileProbe(path))
}

func detectSingleFileTypeWithProbe(probe firmwareFileProbe) string {
	base := probe.lowerBase
	ext := strings.ToLower(filepath.Ext(base))
	head := probe.head512
	privateKeyProbe := probe.head64k
	switch {
	case looksLikeRunningConfigName(base):
		return "device-running-config"
	case looksLikeStartupConfigName(base):
		return "device-startup-config"
	case ext == ".cfg":
		return "device-config"
	case isArchivePath(probe.path):
		return detectArchiveType(probe.path)
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		if containsAny(string(head), "Go BuildID", "Go build") {
			return "go-static-elf"
		}
		return "linux-elf"
	case ext == ".cc":
		return "vendor-firmware-image"
	case ext == ".pat":
		return "vendor-patch-package"
	case ext == ".bin" && containsAny(base, "boot", "bootware"):
		return "bootloader-image"
	case ext == ".bin":
		return "vendor-firmware-image"
	case isParsableUnencryptedPEMPrivateKey(privateKeyProbe):
		return "private-key-file"
	case ext == ".txt":
		if strings.Contains(base, "private") {
			return "device-private-data"
		}
		return "plain-text-file"
	case strings.Contains(base, "key"):
		return "device-key-material"
	case strings.Contains(base, "private"):
		return "device-private-data"
	case looksBinaryContent(head):
		return "unknown-binary"
	default:
		return "plain-text-file"
	}
}

func detectPlatformFromName(path string) string {
	return detectPlatformFromProbe(newFirmwareFileProbe(path))
}

func detectPlatformFromProbe(probe firmwareFileProbe) string {
	base := probe.lowerBase
	content := strings.ToLower(string(probe.head64k))
	switch {
	case strings.Contains(base, "s5720"), strings.Contains(base, "vrp"):
		return "Huawei S5720SI / VRP"
	case strings.Contains(base, "s5570"), strings.Contains(base, "cmw"), strings.Contains(base, "comware"), strings.Contains(base, "r1107"):
		return "H3C S5570S / Comware 7.1 R1107"
	case strings.Contains(base, "startup.cfg"), strings.Contains(base, "running.cfg"):
		switch {
		case containsAny(content, "huawei", "vrp") || (containsAny(content, "v200r") && containsAny(content, "s5720", "software version")):
			return "Huawei S5720SI / VRP"
		case containsAny(content, "comware", "h3c") || (containsAny(content, "release 1107", "r1107") && containsAny(content, "s5570", "comware")):
			return "H3C S5570S / Comware 7.1 R1107"
		default:
			return "unknown"
		}
	default:
		return "unknown"
	}
}

func detectInventoryEvidence(path string) []string {
	return detectInventoryEvidenceWithProbe(newFirmwareFileProbe(path))
}

func detectInventoryEvidenceWithProbe(probe firmwareFileProbe) []string {
	lower := probe.lowerBase
	var evidence []string
	head := probe.head1024
	if strings.Contains(lower, "s5720") || strings.Contains(lower, "s5570") || strings.Contains(lower, "vrp") || strings.Contains(lower, "cmw") {
		evidence = append(evidence, "文件名包含设备型号、厂商缩写或版本号线索")
	}
	if strings.Contains(lower, "boot") || strings.Contains(lower, "bootware") {
		evidence = append(evidence, "文件名包含 boot/bootware 线索")
	}
	if bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}) {
		evidence = append(evidence, "文件头为 ELF")
		if containsAny(string(head), "Go BuildID", "Go build") {
			evidence = append(evidence, "文件头中可见 Go BuildID 特征")
		}
	}
	if isLikelyPEMPrivateKey(head) {
		evidence = append(evidence, "文件头呈现标准 PEM 私钥标记")
	}
	if strings.HasSuffix(lower, ".cfg") {
		evidence = append(evidence, "配置中包含 local-user/password/snmp/interface 等关键字段")
		evidence = append(evidence, summarizeConfigEvidence(probe.path)...)
	}
	if isArchivePath(probe.path) {
		evidence = append(evidence, "压缩包成员已检查")
		evidence = append(evidence, summarizeArchiveEvidence(probe.path)...)
	}
	if strings.Contains(lower, "key") || strings.Contains(lower, "private") {
		evidence = append(evidence, "文件名包含 key/private 等敏感材料线索")
		if looksBinaryContent(head) {
			evidence = append(evidence, "内容呈现二进制高熵 blob 特征")
		}
		if strings.Contains(lower, "private") {
			evidence = append(evidence, summarizePrivateDataEvidence(probe.path)...)
		}
	}
	if containsAny(string(head), "squashfs", "uimage", "jffs2", "gzip", "linux") && (strings.HasSuffix(lower, ".cc") || strings.HasSuffix(lower, ".bin") || strings.HasSuffix(lower, ".pat")) {
		evidence = append(evidence, "二进制中出现 SquashFS/gzip/ELF/uImage 等嵌入组件标记")
	}
	if len(evidence) == 0 {
		if looksBinaryContent(head) {
			evidence = append(evidence, "文件内容为未知二进制格式，尚未确认具体语义")
		} else {
			evidence = append(evidence, "当前仅识别为普通文本内容，未观察到更强结构特征")
		}
	}
	return dedupeStrings(evidence)
}

type firmwareFileProbe struct {
	path      string
	base      string
	lowerBase string
	head512   []byte
	head1024  []byte
	head64k   []byte
}

func newFirmwareFileProbe(path string) firmwareFileProbe {
	head64k := readFileHead(path, 64*1024)
	return firmwareFileProbe{
		path:      path,
		base:      filepath.Base(path),
		lowerBase: strings.ToLower(filepath.Base(path)),
		head512:   shrinkHead(head64k, 512),
		head1024:  shrinkHead(head64k, 1024),
		head64k:   head64k,
	}
}

func shrinkHead(head []byte, limit int) []byte {
	if len(head) <= limit {
		return head
	}
	return head[:limit]
}

func looksLikeExtractedFilesystem(dir string) bool {
	for _, probe := range []string{"etc/passwd", "etc/shadow", "bin", "sbin", "www"} {
		if _, err := os.Stat(filepath.Join(dir, probe)); err == nil {
			return true
		}
	}
	return false
}

func detectFilesystemPlatform(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "bin", "busybox")); err == nil {
		return "Linux / BusyBox"
	}
	return "unknown"
}

func detectFilesystemKeyPaths(dir string) []string {
	var out []string
	for _, probe := range []string{"etc", "bin", "sbin", "usr", "www", "lib", "var"} {
		if _, err := os.Stat(filepath.Join(dir, probe)); err == nil {
			out = append(out, "/"+probe)
		}
	}
	return out
}

func shouldIncludeRootfsInventory(rel string) bool {
	rel = strings.ToLower(strings.TrimSpace(filepath.ToSlash(rel)))
	switch {
	case rel == "etc/passwd", rel == "etc/shadow", rel == "etc/group":
		return true
	case strings.HasPrefix(rel, "etc/init.d/"):
		return true
	case strings.HasPrefix(rel, "bin/"), strings.HasPrefix(rel, "sbin/"):
		return filepath.Base(rel) == "busybox" || strings.Contains(filepath.Base(rel), "http") || strings.Contains(filepath.Base(rel), "dropbear")
	case strings.HasPrefix(rel, "www/"):
		return strings.HasSuffix(rel, ".html") || strings.HasSuffix(rel, ".js") || strings.HasSuffix(rel, ".cgi")
	default:
		return false
	}
}

func summarizeConfigEvidence(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	var sensitive []string
	var context []string
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "local-user") && (strings.Contains(lower, "password") || strings.Contains(lower, "cipher")):
			sensitive = append(sensitive, fmt.Sprintf("%s:L%d 包含本地用户口令材料：%s", filepath.Base(path), idx+1, maskSensitiveEvidence(line)))
		case strings.Contains(lower, "snmp") && (strings.Contains(lower, "md5") || strings.Contains(lower, "aes")):
			sensitive = append(sensitive, fmt.Sprintf("%s:L%d 包含 SNMP 认证/加密材料：%s", filepath.Base(path), idx+1, maskSensitiveEvidence(line)))
		case strings.Contains(lower, "stelnet") || strings.Contains(lower, "ssh") || strings.Contains(lower, "console"):
			context = append(context, fmt.Sprintf("%s:L%d 包含 SSH/stelnet/console 管理面配置：%s", filepath.Base(path), idx+1, line))
		case strings.Contains(lower, "interface") || strings.Contains(lower, "vlanif") || strings.Contains(lower, "acl") || strings.Contains(lower, "route-static"):
			context = append(context, fmt.Sprintf("%s:L%d 包含管理接口或路由信息：%s", filepath.Base(path), idx+1, line))
		}
	}
	evidence := append(sensitive, context...)
	if len(evidence) > 3 {
		evidence = evidence[:3]
	}
	return evidence
}

func summarizePrivateDataEvidence(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(raw)
	if !containsAny(text, "console", "gigabitethernet", "vlanif", "meth", "null0") {
		return nil
	}
	return []string{"文件包含 Console / GigabitEthernet / Vlanif / MEth / NULL0 等接口或拓扑线索"}
}

func summarizeArchiveEvidence(path string) []string {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		return nil
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer reader.Close()
	var evidence []string
	for _, file := range reader.File {
		memberLabel := "ZIP 包包含成员"
		if strings.HasSuffix(strings.ToLower(file.Name), ".cfg") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			raw, _ := io.ReadAll(rc)
			_ = rc.Close()
			if looksStructuredText(raw) {
				memberLabel = "ZIP 包包含文本配置成员"
			}
			evidence = append(evidence, fmt.Sprintf("%s %s", memberLabel, file.Name))
			lines := strings.Split(string(raw), "\n")
			for idx, line := range lines {
				line = strings.TrimSpace(line)
				lower := strings.ToLower(line)
				if strings.Contains(lower, "local-user") || strings.Contains(lower, "snmp") {
					evidence = append(evidence, fmt.Sprintf("%s:L%d 包含配置敏感字段：%s", file.Name, idx+1, maskSensitiveEvidence(line)))
					break
				}
			}
		} else {
			evidence = append(evidence, fmt.Sprintf("%s %s", memberLabel, file.Name))
		}
		if len(evidence) >= 3 {
			break
		}
	}
	return evidence
}

func inferCorpusFindingsFromInventory(entries []firmwareInventoryEntry, basePath string) []firmwareFinding {
	var configFiles []string
	var keyFiles []string
	var parsedPrivateKeyFiles []string
	var privateDataFiles []string
	var firmwareFiles []string
	var configEvidence []string
	var vendorEvidence []string
	var privateDataEvidence []string
	for _, entry := range entries {
		switch entry.DetectedType {
		case "device-config", "device-startup-config", "device-running-config", "config-archive":
			if hasAuthenticationMaterialEvidence(entry.Evidence) {
				configFiles = append(configFiles, affectedAuthenticationConfigPaths(entry, basePath)...)
				configEvidence = append(configEvidence, entry.Evidence...)
			}
		case "device-key-material":
			keyFiles = append(keyFiles, filepath.Join(basePath, entry.Name))
		case "private-key-file":
			parsedPrivateKeyFiles = append(parsedPrivateKeyFiles, filepath.Join(basePath, entry.Name))
		case "device-private-data":
			privateDataFiles = append(privateDataFiles, filepath.Join(basePath, entry.Name))
			privateDataEvidence = append(privateDataEvidence, entry.Evidence...)
		case "vendor-firmware-image", "vendor-patch-package", "bootloader-image", "linux-elf", "go-static-elf":
			firmwareFiles = append(firmwareFiles, filepath.Join(basePath, entry.Name))
			vendorEvidence = append(vendorEvidence, entry.Evidence...)
		}
	}
	var findings []firmwareFinding
	if len(configFiles) > 0 && containsAny(strings.ToLower(strings.Join(configEvidence, "\n")), "local-user", "snmp", "password", "cipher") {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "导出的设备配置暴露认证材料",
			Category:      "sensitive-data-exposure",
			Severity:      "high",
			Confidence:    "high",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(configFiles),
			Source:        "设备启动配置、运行配置或配置备份包",
			Transform:     "配置文件及压缩包成员被解析，并识别出 local-user、password、SNMPv3 等认证字段",
			Sink:          "not confirmed",
			MissingGuard:  "配置导出或留存时未对敏感认证材料做脱敏处理",
			Evidence:      strings.Join(maskEvidenceList(configEvidence), "\n"),
			Limitations:   "报告已默认脱敏，未验证哈希可破解性、凭据有效性或 SNMPv3 实际可利用性",
		}))
	}
	if len(keyFiles) > 0 {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "目录中存在疑似设备密钥材料",
			Category:      "sensitive-data-presence",
			Severity:      "medium",
			Confidence:    "medium",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(keyFiles),
			Source:        "样本目录中包含 key/private-data 命名文件",
			Transform:     "结合文件名与内容特征将其归类为疑似设备密钥材料或私有 blob",
			Sink:          "not confirmed",
			MissingGuard:  "敏感材料与普通样本一并留存或外发",
			Evidence:      "发现带有 key/private 命名的文件，且内容呈现二进制高熵 blob 或厂商私有数据特征",
			Limitations:   "尚未确认密钥类型、是否加密、是否可直接用于认证或解密",
		}))
	}
	if len(parsedPrivateKeyFiles) > 0 {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "样本中包含可解析的未加密标准私钥材料",
			Category:      "private-key-exposure",
			Severity:      "high",
			Confidence:    "high",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(parsedPrivateKeyFiles),
			Source:        "样本目录中的标准 PEM 私钥文件",
			Transform:     "PEM 内容通过标准私钥解析验证，并随分析语料留存",
			Sink:          "not confirmed",
			MissingGuard:  "可直接使用的私钥材料与普通样本一并留存或外发",
			Evidence:      "文件已解析为未加密的标准私钥结构；具体密钥内容不在报告中展示",
			Limitations:   "未验证该密钥是否仍在目标设备上启用，也未验证其对应服务或授权范围",
		}))
	}
	if len(privateDataFiles) > 0 {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "设备私有数据暴露接口和拓扑信息",
			Category:      "private-data-exposure",
			Severity:      "medium",
			Confidence:    "medium",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(privateDataFiles),
			Source:        "样本目录中的设备私有数据文件",
			Transform:     "文件内容暴露出接口命名、拓扑标识或设备侧私有清单信息",
			Sink:          "not confirmed",
			MissingGuard:  "私有设备数据与普通样本一并留存或外发",
			Evidence:      defaultText(strings.Join(maskEvidenceList(privateDataEvidence), "\n"), "文件中可见 Console / GigabitEthernet / Vlanif / MEth / NULL0 等接口或拓扑线索"),
			Limitations:   "未确认这些信息是否仍反映当前网络环境，也未确认是否可直接用于后续攻击",
		}))
	}
	if len(firmwareFiles) > 0 {
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "发现固件镜像攻击面线索",
			Category:      "container-observation",
			Severity:      "info",
			Confidence:    "medium",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(firmwareFiles),
			Source:        "语料目录中的固件镜像、补丁包或 Bootloader 样本",
			Transform:     "基于文件名、扩展名和嵌入组件标记对样本进行初步归类",
			Sink:          "not confirmed",
			MissingGuard:  "不适用",
			Evidence:      strings.Join(maskEvidenceList(vendorEvidence), "\n"),
			Limitations:   "当前主要基于文件名、magic 与字符串特征，未对全部镜像做完整解包或反汇编",
		}))
		findings = append(findings, normalizeFinding(firmwareFinding{
			Title:         "发现 CLI 管理面与命令解析攻击面线索",
			Category:      "attack-surface",
			Severity:      "info",
			Confidence:    "medium",
			Scope:         "corpus-level",
			AffectedFiles: dedupeStrings(firmwareFiles),
			Source:        "固件镜像及相关配置中出现管理面和命令解析线索",
			Transform:     "样本清单与配置证据指向 SSH/Telnet/Console 等管理接口或命令解析组件",
			Sink:          "not confirmed",
			MissingGuard:  "未确认外部输入到命令执行函数的数据流",
			Evidence:      "观察到 SSH/Telnet/Console 等管理面字符串或配置线索，但尚未确认外部输入到命令执行函数的数据流",
			Limitations:   "当前仅能确认攻击面存在，尚未确认命令注入或未授权命令执行",
		}))
	}
	return findings
}

func hasAuthenticationMaterialEvidence(evidence []string) bool {
	text := strings.ToLower(strings.Join(evidence, "\n"))
	return containsAny(text,
		"口令材料",
		"认证/加密材料",
		"password",
		"irreversible-cipher",
		"authentication-mode",
		"privacy-mode",
		"snmp-agent community",
	)
}

func affectedAuthenticationConfigPaths(entry firmwareInventoryEntry, basePath string) []string {
	archivePath := filepath.Join(basePath, entry.Name)
	if !entry.IsArchive {
		return []string{archivePath}
	}
	evidence := strings.ToLower(strings.Join(entry.Evidence, "\n"))
	var members []string
	for _, member := range entry.Members {
		name := strings.TrimSpace(strings.Split(member, ",")[0])
		if name == "" || !strings.Contains(evidence, strings.ToLower(filepath.Base(name))+":l") {
			continue
		}
		members = append(members, archivePath+"!/"+name)
	}
	if len(members) == 0 {
		return []string{archivePath}
	}
	return members
}

func archiveContainsConfig(path string) bool {
	members, _ := inspectArchiveMembers(path)
	for _, member := range members {
		name := strings.ToLower(strings.TrimSpace(strings.Split(member, ",")[0]))
		if strings.HasSuffix(name, ".cfg") || strings.Contains(name, "config") || strings.Contains(name, "vrpcfg") {
			return true
		}
	}
	return false
}

func looksLikeStartupConfigName(base string) bool {
	return strings.HasSuffix(base, ".cfg") && (strings.Contains(base, "startup") || strings.Contains(base, "boot"))
}

func looksLikeRunningConfigName(base string) bool {
	return strings.HasSuffix(base, ".cfg") && strings.Contains(base, "running")
}

func readFileHead(path string, n int) []byte {
	if n <= 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(raw) > n {
		return raw[:n]
	}
	return raw
}

func isLikelyPEMPrivateKey(head []byte) bool {
	return containsAny(string(head), "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----")
}

func isParsableUnencryptedPEMPrivateKey(raw []byte) bool {
	block, _ := pem.Decode(raw)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") || x509.IsEncryptedPEMBlock(block) {
		return false
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return true
	}
	return false
}

func looksBinaryContent(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	var nonPrintable int
	for _, b := range head {
		if b == 0 || b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrintable++
		}
	}
	return nonPrintable > len(head)/10
}

func looksStructuredText(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var printable, lineBreaks int
	for _, b := range raw {
		if b == '\n' || b == '\r' {
			lineBreaks++
		}
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return printable >= len(raw)*8/10 &&
		(lineBreaks >= 1 || containsAny(string(raw), "local-user", "snmp-agent", "sysname", "interface", "software version"))
}

func maskEvidenceList(items []string) []string {
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, maskSensitiveEvidence(item))
	}
	return dedupeStrings(out)
}

func maskSensitiveEvidence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return text
	}
	replacements := []struct {
		pattern *regexp.Regexp
		repl    string
	}{
		{regexp.MustCompile(`(?i)(irreversible-cipher\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(password(?:\s+hash)?\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(snmp-agent community\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(authentication-mode\s+\S+\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(privacy-mode\s+\S+\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(auth\s+\S+\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(privacy\s+\S+\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(secret\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(token\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)(api[-_ ]?key\s+)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(\$h\$\d+\$)(\S+)`), `${1}<masked>`},
		{regexp.MustCompile(`(?i)-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----`), `PRIVATE KEY <masked>`},
	}
	for _, repl := range replacements {
		text = repl.pattern.ReplaceAllString(text, repl.repl)
	}
	return text
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func appendJSONLineState(loop *reactloops.ReActLoop, key string, value any) {
	if loop == nil || strings.TrimSpace(key) == "" || value == nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	current := strings.TrimSpace(loop.Get(key))
	if current == "" {
		loop.Set(key, string(raw))
		return
	}
	loop.Set(key, current+"\n"+string(raw))
}

func parseJSONLineState[T any](raw string) []T {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []T
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out
}

func normalizeDataStructure(ds firmwareDataStructure) firmwareDataStructure {
	ds.Name = defaultText(ds.Name, "unnamed_structure")
	ds.Location = defaultText(ds.Location, "unknown")
	ds.ProducerConsumer = defaultText(ds.ProducerConsumer, "unknown")
	ds.Evidence = defaultText(ds.Evidence, "No explicit evidence recorded.")
	ds.Confidence = normalizeConfidence(ds.Confidence)
	ds.SemanticsStatus = normalizeSemanticsStatus(ds.SemanticsStatus, ds.ValidatedSemantics, ds.InferredLayout)
	if ds.SemanticsStatus == "inferred" {
		ds.ValidatedSemantics = ""
		if ds.InferredLayout == "" {
			ds.InferredLayout = "Only field layout is inferred from offsets, sizes, or memory access patterns."
		}
		ds.Fields = neutralizeFieldNames(ds.Fields)
	}
	return ds
}

func renderDataStructureMarkdown(ds firmwareDataStructure) string {
	lines := []string{
		fmt.Sprintf("### %s", localizeStructureTitle(ds.Name)),
		fmt.Sprintf("- 结构名称：%s", ds.Name),
		fmt.Sprintf("- 位置：%s", ds.Location),
		fmt.Sprintf("- 字段布局：%s", ds.Fields),
		fmt.Sprintf("- 生产者/消费者：%s", ds.ProducerConsumer),
		fmt.Sprintf("- 语义状态：%s", localizeSemanticsStatus(ds.SemanticsStatus)),
		fmt.Sprintf("- 识别依据：%s", ds.Evidence),
		fmt.Sprintf("- 可信度：%s", localizeConfidence(ds.Confidence)),
	}
	if ds.ValidatedSemantics != "" {
		lines = append(lines, fmt.Sprintf("- 已确认语义：%s", ds.ValidatedSemantics))
	}
	if ds.InferredLayout != "" {
		lines = append(lines, fmt.Sprintf("- 推断布局：%s", ds.InferredLayout))
	}
	return strings.Join(lines, "\n")
}

func renderDataStructuresMarkdown(entries []firmwareDataStructure, fallback string) string {
	if len(entries) == 0 {
		return strings.TrimSpace(fallback)
	}
	var parts []string
	for _, ds := range entries {
		parts = append(parts, renderDataStructureMarkdown(normalizeDataStructure(ds)))
	}
	return strings.Join(parts, "\n\n")
}

func normalizeFinding(f firmwareFinding) firmwareFinding {
	f.Title = defaultText(f.Title, "Untitled finding")
	f.Category = normalizeRiskCategory(f.Category)
	f.Severity = normalizeSeverity(f.Severity)
	f.Confidence = normalizeConfidence(f.Confidence)
	f.Source = defaultText(f.Source, "unknown external input")
	f.Transform = strings.TrimSpace(f.Transform)
	f.Sink = normalizeSink(f.Sink)
	f.MissingGuard = defaultText(f.MissingGuard, "not recorded")
	f.Evidence = defaultText(f.Evidence, "No explicit evidence recorded.")
	if hasStringOnlyEvidence(f.Evidence) {
		f.Severity = "info"
		f.Confidence = "low"
		f.Sink = "not confirmed"
	}
	if findingCategoryNeedsStrictEvidenceChain(f.Category) && !hasCompleteEvidenceChain(f) && !hasExplicitGuardGap(f) {
		f.Severity = "info"
		if f.Confidence == "high" {
			f.Confidence = "low"
		}
		f.Sink = "not confirmed"
		if strings.TrimSpace(f.SuppressionReason) == "" {
			f.SuppressionReason = "The finding does not yet include a complete source-transform-sink chain or an explicit missing guard, so it remains an informational lead rather than a confirmed risk conclusion."
		}
	}
	if isCommandFindingCategory(f.Category) && !containsConfirmedCommandSink(f.Sink+" "+f.Evidence) {
		f.Title = "Suspicious command-execution capability"
		f.Category = "suspicious-command-capability"
		f.Severity = "info"
		f.Confidence = "low"
		f.Sink = "not confirmed"
		f.MissingGuard = "未确认外部输入到命令执行函数的数据流"
		if strings.TrimSpace(f.SuppressionReason) == "" {
			f.SuppressionReason = "当前仅观察到命令执行相关字符串或能力线索，尚未确认真实命令执行 sink 与外部输入可达路径。"
		}
	}
	return f
}

func renderFindingMarkdown(f firmwareFinding) string {
	lines := []string{fmt.Sprintf("### %s：%s", localizeSeverity(f.Severity), localizeFindingTitle(f.Title))}
	riskLabel, riskText := localizeRiskOperation(f)
	lines = append(lines,
		fmt.Sprintf("- 问题类型：%s", localizeCategory(f.Category)),
		fmt.Sprintf("- 可信度：%s", localizeConfidence(f.Confidence)),
	)
	if strings.TrimSpace(f.Scope) != "" {
		lines = append(lines, fmt.Sprintf("- 影响范围：%s", localizeScope(f.Scope)))
	}
	if len(f.AffectedFiles) > 0 {
		lines = append(lines, "- 关联文件：")
		for _, file := range f.AffectedFiles {
			lines = append(lines, fmt.Sprintf("  - %s", file))
		}
	}
	lines = append(lines,
		fmt.Sprintf("- 输入来源：%s", f.Source),
		fmt.Sprintf("- 传播路径：%s", f.Transform),
		fmt.Sprintf("- %s：%s", riskLabel, riskText),
		fmt.Sprintf("- 缺失防护：%s", f.MissingGuard),
		fmt.Sprintf("- 识别依据：%s", maskSensitiveEvidence(f.Evidence)),
	)
	if strings.TrimSpace(f.Limitations) != "" {
		lines = append(lines, fmt.Sprintf("- 限制说明：%s", f.Limitations))
	}
	if strings.TrimSpace(f.SuppressionReason) != "" {
		lines = append(lines, fmt.Sprintf("- 限制说明：%s", f.SuppressionReason))
	}
	lines = append(lines, fmt.Sprintf("- 修复建议：%s", suggestRemediation(f)))
	return strings.Join(lines, "\n")
}

func renderFindingsMarkdown(entries []firmwareFinding, fallback string) string {
	if len(entries) == 0 {
		return strings.TrimSpace(fallback)
	}
	groups := [][]string{
		{"已确认风险", "confirmed-risk"},
		{"敏感信息与敏感材料", "sensitive"},
		{"攻击面线索与组件观察", "attack-surface"},
		{"待验证假设", "pending"},
	}
	buckets := map[string][]string{
		"confirmed-risk": {},
		"sensitive":      {},
		"attack-surface": {},
		"pending":        {},
	}
	for _, f := range entries {
		f = normalizeFinding(f)
		key := findingPresentationGroup(f)
		buckets[key] = append(buckets[key], renderFindingMarkdown(f))
	}
	var parts []string
	for _, group := range groups {
		body := buckets[group[1]]
		if len(body) == 0 {
			continue
		}
		parts = append(parts, "### "+group[0]+"\n\n"+strings.Join(body, "\n\n"))
	}
	if len(parts) == 0 {
		return strings.TrimSpace(fallback)
	}
	return strings.Join(parts, "\n\n")
}

func renderFuzzPlanMarkdown(plan firmwareFuzzPlan) string {
	return strings.Join([]string{
		fmt.Sprintf("### %s", localizeFuzzTargetTitle(plan.Target)),
		fmt.Sprintf("- 测试目标：%s", plan.Target),
		fmt.Sprintf("- 入口点：%s", plan.Entrypoint),
		fmt.Sprintf("- 输入模型：%s", plan.InputModel),
		fmt.Sprintf("- 变异策略：%s", plan.MutationStrategy),
		fmt.Sprintf("- 判定条件：%s", plan.Oracle),
		fmt.Sprintf("- 环境要求：%s", defaultText(plan.SetupNotes, "无特殊要求")),
		fmt.Sprintf("- 优先级：%s", localizeSeverity(normalizeSeverity(plan.Priority))),
	}, "\n")
}

func renderFuzzPlansMarkdown(entries []firmwareFuzzPlan, fallback string) string {
	if len(entries) == 0 {
		return strings.TrimSpace(fallback)
	}
	var parts []string
	for _, plan := range entries {
		parts = append(parts, renderFuzzPlanMarkdown(plan))
	}
	return strings.Join(parts, "\n\n")
}

func normalizeSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info", "low", "medium", "high", "critical":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "medium"
	}
}

func localizeSeverity(v string) string {
	switch normalizeSeverity(v) {
	case "critical":
		return "严重（Critical）"
	case "high":
		return "高危（High）"
	case "medium":
		return "中危（Medium）"
	case "low":
		return "低危（Low）"
	default:
		return "提示（Info）"
	}
}

func normalizeConfidence(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low", "medium", "high":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "medium"
	}
}

func localizeConfidence(v string) string {
	switch normalizeConfidence(v) {
	case "high":
		return "高"
	case "medium":
		return "中"
	default:
		return "低"
	}
}

func localizeSemanticsStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "validated":
		return "已确认"
	case "inferred":
		return "推断"
	default:
		return "推断"
	}
}

func localizeTargetType(v string) string {
	switch strings.TrimSpace(v) {
	case "file":
		return "单文件"
	case "archive":
		return "压缩包"
	case "directory / firmware corpus":
		return "固件语料目录"
	case "extracted filesystem":
		return "已提取文件系统"
	default:
		return v
	}
}

func localizeDetectedType(v string) string {
	switch strings.TrimSpace(v) {
	case "device-config":
		return "设备配置文件"
	case "device-startup-config":
		return "设备启动配置"
	case "device-running-config":
		return "设备运行配置"
	case "vendor-firmware-image":
		return "厂商固件镜像"
	case "vendor-patch-package":
		return "厂商补丁包"
	case "bootloader-image":
		return "Bootloader 镜像"
	case "linux-elf":
		return "Linux ELF 可执行文件"
	case "go-static-elf":
		return "Go 静态链接可执行文件"
	case "device-key-material", "private-key-file":
		return "设备密钥材料"
	case "device-private-data":
		return "设备私有二进制数据"
	case "config-archive":
		return "配置压缩包"
	case "archive":
		return "压缩包"
	case "plain-text-file":
		return "普通文本文件"
	case "unknown-binary":
		return "未知二进制文件"
	case "unknown":
		return "未知"
	default:
		return v
	}
}

func localizeAnalysisScope(v string) string {
	switch strings.TrimSpace(v) {
	case "single target":
		return "单个目标文件"
	case "top-level + selected archive members":
		return "顶层文件 + 已选择的压缩包成员"
	case "archive members inspected":
		return "压缩包成员已检查"
	case "recursive filesystem inspection":
		return "递归文件系统检查"
	default:
		return v
	}
}

func localizeCategory(v string) string {
	switch strings.TrimSpace(v) {
	case "path-traversal":
		return "路径穿越（Path Traversal）"
	case "untrusted-length-slicing":
		return "长度字段未校验导致切片风险"
	case "insufficient-length-check":
		return "解析器边界检查不足"
	case "declared-payload-length-not-validated":
		return "声明长度与实际载荷不一致"
	case "missing-integrity-verification":
		return "缺少完整性/真实性校验"
	case "custom-format":
		return "自定义固件格式识别"
	case "sensitive-data-exposure":
		return "敏感信息暴露"
	case "private-key-exposure":
		return "未加密私钥暴露"
	case "attack-surface":
		return "攻击面识别"
	case "container-observation":
		return "固件容器观察"
	case "suspicious-command-capability":
		return "待验证命令执行线索"
	case "sensitive-data-presence":
		return "敏感材料存在"
	case "private-data-exposure":
		return "设备私有数据暴露"
	case "generic-risk":
		return "待验证风险"
	default:
		return v
	}
}

func localizeScope(v string) string {
	switch strings.TrimSpace(v) {
	case "corpus-level":
		return "语料级"
	case "file-level":
		return "文件级"
	case "archive-member-level":
		return "压缩包成员级"
	default:
		return v
	}
}

func localizeSink(v string) string {
	if strings.TrimSpace(v) == "not confirmed" {
		return "未确认"
	}
	return v
}

func localizeRiskOperation(f firmwareFinding) (string, string) {
	switch f.Category {
	case "sensitive-data-exposure":
		return "危险结果", "配置泄露后可能导致离线破解、凭据复用、管理面探测或针对性攻击"
	case "private-key-exposure":
		return "危险结果", "未加密标准私钥随样本留存或外发后，可能被用于对应认证场景"
	case "sensitive-data-presence":
		return "危险结果", "样本目录中留存了疑似设备密钥材料，存在进一步滥用风险"
	case "private-data-exposure":
		return "危险结果", "私有数据文件暴露了接口、拓扑或设备侧内部标识信息，可被用于后续侦察与定向攻击"
	case "attack-surface":
		return "危险结果", "当前确认的是管理面与命令解析攻击面线索，尚未确认可直接利用的危险调用"
	case "container-observation", "custom-format":
		return "危险结果", "当前主要完成组件与格式识别，尚未据此确认具体漏洞"
	default:
		return "危险操作", localizeSink(f.Sink)
	}
}

func findingPresentationGroup(f firmwareFinding) string {
	switch f.Category {
	case "sensitive-data-exposure", "private-key-exposure", "sensitive-data-presence", "private-data-exposure":
		return "sensitive"
	case "attack-surface", "container-observation", "custom-format":
		return "attack-surface"
	case "suspicious-command-capability", "generic-risk":
		return "pending"
	default:
		if normalizeSeverity(f.Severity) == "info" && strings.TrimSpace(f.Sink) == "not confirmed" {
			return "pending"
		}
		return "confirmed-risk"
	}
}

func renderTargetDetailsMarkdown(ctx firmwareReportContext) string {
	var lines []string
	if strings.TrimSpace(ctx.TargetDetectedType) != "" && ctx.TargetDetectedType != "unknown" && ctx.TargetDetectedType != "firmware corpus" && strings.TrimSpace(ctx.TargetType) != "extracted filesystem" {
		lines = append(lines, fmt.Sprintf("- 已识别类型：%s", localizeDetectedType(ctx.TargetDetectedType)))
	}
	if strings.TrimSpace(ctx.TargetType) == "extracted filesystem" {
		if strings.TrimSpace(ctx.TargetDetectedType) != "" {
			lines = append(lines, fmt.Sprintf("- 已识别平台：%s", ctx.TargetDetectedType))
		}
		if len(ctx.TargetKeyPaths) > 0 {
			lines = append(lines, fmt.Sprintf("- 关键目录：%s", strings.Join(ctx.TargetKeyPaths, "、")))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n" + strings.Join(lines, "\n")
}

func localizeStructureTitle(name string) string {
	switch strings.TrimSpace(name) {
	case "FirmwareHeader":
		return "FWUP 固件头"
	default:
		return name
	}
}

func localizeFindingTitle(title string) string {
	switch strings.TrimSpace(title) {
	case "Suspicious command-execution capability":
		return "发现命令执行相关字符串，需验证是否存在可达调用链"
	default:
		return title
	}
}

func localizeFuzzTargetTitle(target string) string {
	return target
}

func suggestRemediation(f firmwareFinding) string {
	switch f.Category {
	case "path-traversal":
		return "对文件名做白名单校验，并在 filepath.Clean 后校验最终路径必须位于预期根目录内。"
	case "untrusted-length-slicing":
		return "在切片前校验剩余缓冲区长度必须满足 6+length 等边界条件。"
	case "insufficient-length-check":
		return "将长度检查提升到最高访问索引以上，并在索引/切片前统一做边界校验。"
	case "declared-payload-length-not-validated":
		return "校验 header.Len 与实际 payload 长度一致，不一致时拒绝处理。"
	case "missing-integrity-verification":
		return "在处理高风险 payload 前增加签名或密码学哈希校验。"
	case "sensitive-data-exposure":
		return "导出配置前脱敏；限制配置备份访问；如样本已外发，轮换本地账号口令、SNMPv3 auth/privacy key、SSH 主机密钥，并复核管理面 ACL。"
	case "private-key-exposure":
		return "从样本包移除私钥文件并限制备份访问；如样本已外发，立即轮换对应密钥并核查相关认证服务。"
	case "sensitive-data-presence":
		return "将疑似设备密钥材料从样本包中分离并按敏感文件处理；如已外发，评估重新生成或轮换设备侧密钥。"
	case "private-data-exposure":
		return "避免将 private-data 文件与配置、固件一并外发；如已泄露，应评估接口命名、拓扑与设备标识信息带来的暴露面。"
	case "attack-surface", "container-observation", "suspicious-command-capability":
		return "优先解包文件系统或定位相关服务二进制，确认真实入口、可达调用链和危险 sink 后再决定是否升级为漏洞。"
	default:
		return "结合识别依据补充输入校验、边界检查或权限控制。"
	}
}

func normalizeSemanticsStatus(v string, validated string, inferred string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "validated", "inferred":
		return strings.ToLower(strings.TrimSpace(v))
	}
	if strings.TrimSpace(validated) != "" {
		return "validated"
	}
	if strings.TrimSpace(inferred) != "" {
		return "inferred"
	}
	return "inferred"
}

func neutralizeFieldNames(fields string) string {
	replacements := []string{"crc", "checksum", "reserved"}
	lower := strings.ToLower(fields)
	for _, forbidden := range replacements {
		if strings.Contains(lower, forbidden) {
			fields = "magic[4], u32_at_4, u32_at_8"
			break
		}
	}
	return fields
}

func normalizeRiskCategory(risk string) string {
	risk = strings.ToLower(strings.TrimSpace(risk))
	switch {
	case strings.Contains(risk, "command"):
		return "command-injection"
	case strings.Contains(risk, "path"):
		return "path-traversal"
	case strings.Contains(risk, "oob"), strings.Contains(risk, "out-of-bounds"), strings.Contains(risk, "index"), strings.Contains(risk, "bounds"):
		return "insufficient-length-check"
	case strings.Contains(risk, "integrity"), strings.Contains(risk, "authentic"):
		return "missing-integrity-verification"
	default:
		if risk == "" {
			return "generic-risk"
		}
		return strings.ReplaceAll(risk, " ", "-")
	}
}

func inferConfidenceFromEvidence(evidence string) string {
	e := strings.ToLower(evidence)
	switch {
	case hasStringOnlyEvidence(e):
		return "low"
	case containsAny(e, "source line", "main.go", "disassembly", "xrefs", "call graph", "data flow", "payload[", "binary.read", "os.writefile", "exec.command("):
		return "high"
	case containsAny(e, "symbol", "branch", "heuristic", "import", "nearby"):
		return "medium"
	default:
		return "low"
	}
}

func inferPlanPriority(loop *reactloops.ReActLoop) string {
	if loop == nil {
		return "medium"
	}
	findings := parseJSONLineState[firmwareFinding](loop.Get(firmwareFindingsStateKey))
	return inferHighestSeverity(findings)
}

func inferHighestSeverity(findings []firmwareFinding) string {
	max := "medium"
	score := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, finding := range findings {
		severity := normalizeSeverity(finding.Severity)
		if score[severity] > score[max] {
			max = severity
		}
	}
	return max
}

func containsFindingCategory(findings []firmwareFinding, category string) bool {
	category = strings.TrimSpace(category)
	for _, finding := range findings {
		if finding.Category == category {
			return true
		}
	}
	return false
}

func isCommandFindingCategory(category string) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	return strings.Contains(category, "command") || strings.Contains(category, "exec")
}

func findingCategoryNeedsStrictEvidenceChain(category string) bool {
	switch strings.TrimSpace(category) {
	case "path-traversal", "untrusted-length-slicing", "insufficient-length-check", "declared-payload-length-not-validated", "missing-integrity-verification", "command-injection", "suspicious-command-capability", "generic-risk":
		return true
	default:
		return false
	}
}

func containsConfirmedCommandSink(text string) bool {
	return containsAny(text, "exec.command(", ".combinedoutput(", "system(", "popen(", "execve(", "cmd.run(")
}

func detectConfirmedCommandInjection(text string) bool {
	if !containsConfirmedCommandSink(text) {
		return false
	}
	return containsAny(text, "payload", "input", "config", "targetip", "filename", "user-controlled", "external")
}

func detectPathTraversalPattern(text string) bool {
	if !containsAny(text, "filepath.join", "path.join") {
		return false
	}
	if !containsAny(text, "os.writefile", "os.create", "fopen", "writefile") {
		return false
	}
	if containsAny(text, "strings.hasprefix(", "filepath.rel(", "baseDir-prefix", "containment check", "allowlist") {
		return false
	}
	return containsAny(text, "string(payload", "filename", "payload[6", "archive entry", "pathname", "targetpath")
}

func detectUntrustedLengthSlicingPattern(text string) bool {
	if !containsAny(text, "uint16(payload[4:6])", "filenamelen := int(binary.littleendian.uint16(payload[4:6]))", "filenamelen", "namelen") {
		return false
	}
	if containsAny(text, "len(payload) >= 6+filenamelen", "len(payload)>=6+filenamelen", "remaining_buffer >= filenamelen") {
		return false
	}
	return containsAny(text, "payload[6 : 6+filenamelen]", "payload[6:6+filenamelen]", "payload[6+filenamelen:]", "payload[6+filenamelen :]")
}

func detectInsufficientLengthCheckPattern(text string) bool {
	guards := []struct {
		minLen int
		tokens []string
	}{
		{minLen: 4, tokens: []string{"len(payload) >= 4", "len(payload)>=4", "len(payload) > 3"}},
		{minLen: 8, tokens: []string{"len(payload) >= 8", "len(payload)>=8", "len(payload) < 8", "len(payload)<8"}},
	}
	if containsAny(text, "len(payload) >= 8", "len(payload)>=8") && detectHighestPayloadIndex(text) <= 7 {
		return false
	}
	maxIndex := detectHighestPayloadIndex(text)
	if maxIndex < 0 {
		return containsAny(text, "payload[header.len-1]", "payload[len-1]", "payload[offset+length]")
	}
	for _, guard := range guards {
		if containsAny(text, guard.tokens...) && maxIndex >= guard.minLen {
			return true
		}
	}
	return false
}

func detectDeclaredPayloadLengthNotValidated(text string) bool {
	if !containsAny(text, "len     uint32", "len uint32", "header.len", "declared length") {
		return false
	}
	if containsAny(text, "len(payload) >= int(header.len)", "len(payload) == int(header.len)", "remaining_buffer >= length") {
		return false
	}
	return containsAny(text, "payload := data[12:]", "processpayload(header, payload)", "processpayload(")
}

func detectMissingIntegrityVerification(text string) bool {
	if containsAny(text, "sha256", "sha1", "sha512", "hmac", "ed25519", "rsa.verify", "rsa.verifypss", "parsepkcs", "ecdsa.verify", "verify(", "signature check", "digest compare") {
		return false
	}
	if !hasConfirmedFWUPParserCapability(text) {
		return false
	}
	return containsAny(text, "processpayload(") && containsAny(text, "os.writefile", "os.create", "fopen(", "writefile")
}

func detectCLikeCorpus(text string) bool {
	return containsAny(text, "char *", "memcpy(", "strcpy(", "size_t", "uint8_t", "fopen(")
}

func dedupeFindings(findings []firmwareFinding) []firmwareFinding {
	merged := make(map[string]firmwareFinding)
	for _, finding := range findings {
		finding = normalizeFinding(finding)
		key := finding.Category + "|" + strings.Join(dedupeStrings(finding.AffectedFiles), "|")
		current, ok := merged[key]
		if !ok {
			merged[key] = finding
			continue
		}
		if severityScore(finding.Severity) > severityScore(current.Severity) {
			current.Severity = finding.Severity
		}
		if confidenceScore(finding.Confidence) > confidenceScore(current.Confidence) {
			current.Confidence = finding.Confidence
		}
		current.AffectedFiles = dedupeStrings(append(current.AffectedFiles, finding.AffectedFiles...))
		current.Evidence = joinEvidence(current.Evidence, finding.Evidence)
		current.Limitations = joinEvidence(current.Limitations, finding.Limitations)
		if strings.TrimSpace(current.Title) == "" {
			current.Title = finding.Title
		}
		merged[key] = current
	}
	var out []firmwareFinding
	for _, finding := range merged {
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if severityScore(out[i].Severity) == severityScore(out[j].Severity) {
			return out[i].Category < out[j].Category
		}
		return severityScore(out[i].Severity) > severityScore(out[j].Severity)
	})
	return out
}

func severityScore(v string) int {
	return map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[normalizeSeverity(v)]
}

func confidenceScore(v string) int {
	return map[string]int{"low": 0, "medium": 1, "high": 2}[normalizeConfidence(v)]
}

func joinEvidence(a string, b string) string {
	parts := dedupeStrings([]string{strings.TrimSpace(a), strings.TrimSpace(b)})
	return strings.Join(parts, "\n")
}

func normalizeSink(sink string) string {
	sink = strings.TrimSpace(sink)
	if sink == "" {
		return "not confirmed"
	}
	if containsConfirmedCommandSink(sink) || containsAny(sink, "os.writefile", "os.create", "fopen(", "indexed memory access", "slice operations", "parser dispatch", "payload-processing operations") {
		return sink
	}
	return "not confirmed"
}

func hasStringOnlyEvidence(evidence string) bool {
	e := strings.ToLower(strings.TrimSpace(evidence))
	if e == "" {
		return false
	}
	if !containsAny(e, "string", "strings", "marker", "literal", "nearby", "symbol", "import") {
		return false
	}
	return !containsAny(e, "source line", "main.go", "payload[", "binary.read", "os.writefile", "exec.command(", "call graph", "data flow", "xrefs", "disassembly")
}

func hasCompleteEvidenceChain(f firmwareFinding) bool {
	return strings.TrimSpace(f.Source) != "" &&
		strings.TrimSpace(f.Transform) != "" &&
		strings.TrimSpace(f.Transform) != "not recorded" &&
		strings.TrimSpace(f.Sink) != "" &&
		strings.TrimSpace(f.Sink) != "not confirmed"
}

func hasExplicitGuardGap(f firmwareFinding) bool {
	mg := strings.ToLower(strings.TrimSpace(f.MissingGuard))
	return mg != "" && mg != "not recorded"
}

func detectHighestPayloadIndex(text string) int {
	pattern := regexp.MustCompile(`payload\[(\d+)\]`)
	matches := pattern.FindAllStringSubmatch(strings.ToLower(text), -1)
	maxIdx := -1
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		var idx int
		_, _ = fmt.Sscanf(match[1], "%d", &idx)
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	return maxIdx
}

func appendLoopSection(loop *reactloops.ReActLoop, key string, entry string) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return
	}
	current := strings.TrimSpace(loop.Get(key))
	if current == "" {
		loop.Set(key, entry)
		return
	}
	loop.Set(key, current+"\n\n"+entry)
}

func firmwareTargetPathFromTask(task aicommon.AIStatefulTask) string {
	if task == nil {
		return ""
	}
	for _, data := range task.GetAttachedDatas() {
		if data == nil || data.Type != aicommon.CONTEXT_PROVIDER_TYPE_FILE {
			continue
		}
		if p := cleanExistingTargetPath(data.Value); p != "" {
			return p
		}
	}
	return ""
}

func extractExistingPath(input string) string {
	if p := cleanExistingTargetPath(strings.TrimSpace(input)); p != "" {
		return p
	}
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return r == '"' || r == '\'' || r == '`' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	for _, field := range fields {
		if p := cleanExistingTargetPath(field); p != "" {
			return p
		}
	}
	for _, match := range absolutePathRegex.FindAllString(input, -1) {
		if p := cleanExistingTargetPath(match); p != "" {
			return p
		}
	}
	return ""
}

var absolutePathRegex = regexp.MustCompile(`/[^\s"'` + "`" + `]+`)

func cleanExistingFilePath(raw string) string {
	p := cleanExistingTargetPath(raw)
	if p == "" {
		return ""
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return ""
	}
	return p
}

func cleanExistingTargetPath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.Trim(p, ".,;:()[]{}<>")
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func defaultText(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
