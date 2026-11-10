# AI platform deployment patterns

CyberForge Server Edition coordinates AI endpoints. It is not itself a model runtime, GPU scheduler or model-weight distribution platform.

## Pattern A: one Linux host, local-first

- Ollama for straightforward local model lifecycle and an OpenAI-compatible endpoint.
- llama.cpp server for GGUF-oriented CPU/GPU deployments and fine-grained runtime configuration.
- Keep model weights on a dedicated data volume; do not place large weights under `/opt/cyberforge-server`.
- Set `CF_AI_BILLING_MODE=local`; use a loopback endpoint and no provider API key where the runtime permits it.

## Pattern B: dedicated GPU serving node

- Use vLLM or NVIDIA Triton on a GPU host with the correct vendor driver/runtime installed by the operator.
- Configure vLLM/Triton as a distinct AI deployment in `CF_AI_DEPLOYMENTS_JSON`.
- Use the runtime's own tensor/pipeline/data parallel features when supported by the chosen model and topology.
- CyberForge records the endpoint and governance settings; it does not schedule CUDA kernels, move model shards or install GPU drivers.

## Pattern C: multi-provider gateway

- Place LiteLLM or another OpenAI-compatible gateway in front of local and paid providers.
- Use separate deployment IDs for local/free/paid routes.
- For paid routes, supply accurate current token prices, explicit `CF_AI_ALLOW_PAID=1`, a per-request cap, and a daily budget.
- Decide whether LiteLLM or CyberForge is the authoritative quota/budget layer. Do not assume two independent estimates are identical.
- CyberForge reserves an estimated request cost atomically in SQLite before a paid call; the reservation is replaced with returned usage after completion and expires if a process crashes or stalls. Provider billing remains authoritative.

## Pattern D: retrieval and application context

- Qdrant is listed as an optional vector-store integration point. The v2.0.1 source release does not bundle a complete ingestion, embedding, chunking, ACL-aware retrieval or document lifecycle service.
- Keep tenant boundaries and document ACLs in the upstream RAG service until a dedicated RAG module is implemented.
- Never index secrets, credential files, or evidence by default.

## v2.0.1 AI Control Plane

- A persistent SQLite model registry mirrors the configured `CF_AI_DEPLOYMENTS_JSON` entries. Enabled state, default route, priority and per-deployment concurrency policies survive restart. Endpoint secrets are never copied into the registry.
- Manual model health probes call only the configured OpenAI-compatible `/models` path. Remote endpoints must be HTTPS and the hostname must be present in `CF_AI_ALLOWED_HOSTS`; redirects are not followed and probe bodies are discarded.
- Health-aware routing uses the latest recorded health state. Automatic selection is restricted to local/free deployments. A manually requested unhealthy local/free model may fail over only to another deployment with the same billing class. Paid deployments are never selected automatically and are never used as automatic failover targets.
- The bounded AI job queue supports high/normal/low priority, fixed worker counts, per-model concurrency limits and small dispatch cohorts. The dispatcher reserves a worker slot before submitting to the executor, preventing the executor's unbounded internal queue from bypassing the configured queue limit. Queue telemetry separates waiting and in-flight jobs. These are scheduler cohorts, not tensor batches. Actual continuous/tensor batching is handled by vLLM/Triton/other inference runtimes.
- Job prompts and answers are not stored in SQLite. SQLite stores job metadata only; results are held in a bounded process-memory cache. After a server restart, queued/running jobs are marked interrupted and are not replayed. Completed result data may be unavailable after process restart or cache eviction.
- GPU inventory runs fixed read-only `nvidia-smi`, `rocm-smi` and `xpu-smi` commands with short timeouts and output bounds. It is not a full GPU telemetry/alerting stack; use DCGM Exporter, ROCm exporters or vendor tooling for production metrics.

### Scheduler sizing

```ini
CF_AI_WORKERS=4
CF_AI_QUEUE_LIMIT=256
CF_AI_COHORT_SIZE=8
CF_AI_COHORT_WAIT_MS=25
```

`CF_AI_WORKERS` is clamped to 1–32, queue capacity to 8–4096, cohort size to 1–16 and wait window to 0–200 ms. Start small on CPU-only hosts. Model concurrency is configurable per deployment from 1–32 in the model registry. Monitor upstream runtime queueing and VRAM before raising these values.

## AI observability

- Use OpenTelemetry Collector as a vendor-neutral telemetry pipeline.
- Prometheus/Grafana for metrics and dashboards; Loki for logs; Tempo for traces; Langfuse for LLM tracing/evaluation where configured.
- The current CyberForge exporter provides basic control-plane metrics. Full OTLP receiver/exporter pipelines and automatic trace instrumentation are provided by the relevant observability components, not by the v2.0.1 control plane.

## Hardware sizing

There is no universal RAM/VRAM promise. Model size, quantization, context length, concurrency, KV cache, batching and architecture all affect capacity. Test the selected model under representative prompts and concurrent load. Keep the CyberForge control plane on a modest separate service footprint where possible; allocate GPU and large memory pools to the model runtime.

## References

- vLLM documentation: https://docs.vllm.ai/
- LiteLLM documentation: https://docs.litellm.ai/
- Ollama documentation: https://docs.ollama.com/
- OpenTelemetry Collector: https://opentelemetry.io/docs/collector/
- Langfuse documentation: https://langfuse.com/docs


## v2.0.2 distributed AI data plane

- Shared model registry, token identity, spend ledger and job metadata live in PostgreSQL when `CF_STORAGE_BACKEND=postgres`.
- A bounded number of control-plane workers claim queued jobs using `FOR UPDATE SKIP LOCKED`; model-slot leases are shared across replicas.
- Prompt payloads and results use AES-256-GCM envelopes with per-job AAD. The same external `CF_DISTRIBUTED_DATA_KEY` must be provisioned to every replica.
- Redis is optional for heartbeats and notifications only. PostgreSQL polling keeps job dispatch operational if Redis is down.
- Delivery is at-least-once for local/free jobs after lease expiry. Paid jobs are not automatically replayed because provider acceptance may have occurred before worker failure.
- No built-in GPU scheduler, model weight distributor, cross-node tensor parallel orchestration or Kubernetes operator is included. Inference remains the responsibility of Ollama, vLLM, Triton, llama.cpp or a configured gateway.
